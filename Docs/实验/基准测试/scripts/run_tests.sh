#!/bin/bash
# ============================================================
# AstralLight - Single Test Run with Full Reports
# ============================================================
# Usage:
#   bash run_tests.sh [OPTIONS]
#
# Options:
#   --skip-build      Skip Maven compilation
#   --module <name>   Test specific module only (general|identity|trustgraph)
#   --with-pit        Include PIT mutation testing (~10min)
#   --no-jacoco       Disable JaCoCo coverage report
#   --help            Show this help
#
# Default: single run, Surefire + JaCoCo, all modules
# ============================================================

set -euo pipefail

# ---- Configuration ----
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="docker/docker-compose-test.yml"
REPORT_BASE="test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

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
            sed -n '2,13p' "$0" | sed 's/^# \?//'
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

# ============================================================
# Main
# ============================================================

log "AstralLight Single Test Runner"
log "Project root: ${PROJECT_ROOT}"
log "Modules: ${MODULES}"
log "JaCoCo: ${WITH_JACOCO}, PIT: ${WITH_PIT}"
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

# ---- Step 3: Setup report directory ----
run_dir="${REPORT_BASE}/run_${TIMESTAMP}"
mkdir -p "$run_dir"
log "Report directory: ${run_dir}"

# ---- Step 4: Clean local artifacts ----
for mod in $(echo "$MODULES" | tr ',' ' '); do
    rm -rf "${PROJECT_ROOT}/${mod}/target/surefire-reports"
    rm -rf "${PROJECT_ROOT}/${mod}/target/site/jacoco"
    rm -rf "${PROJECT_ROOT}/${mod}/target/pit-reports"
done

# ---- Step 5: Build Maven command ----
mvn_props="${REMOTE_TEST_PROP} ${SUREFIRE_OPTS}"
# Use 'verify' when JaCoCo is enabled (report bound to verify phase in AstralGeneral)
if [ "$WITH_JACOCO" = true ]; then
    mvn_goals="verify"
else
    mvn_goals="test"
fi

if [ "$WITH_PIT" = true ]; then
    mvn_goals="test pitest:mutationCoverage"
fi

# ---- Step 6: Execute tests ----
start_time=$(date +%s)

export MAVEN_OPTS="$MAVEN_OPTS"
cd "$PROJECT_ROOT"

# Test execution timeout (seconds) — prevents infinite hangs from Redis reconnection loops
TEST_TIMEOUT=${TEST_TIMEOUT:-1800}

# Background progress indicator — prints elapsed time every 30s
progress_pid=""
(
    while true; do
        sleep 30
        local elapsed=$(($(date +%s) - start_time))
        log "  [progress] Test execution running... ${elapsed}s elapsed"
    done
) &
progress_pid=$!

exit_code=0
# Use stdbuf -oL for line buffering to prevent pipe stalls with tee
# Remove -q flag to show test progress in real time
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
    log "WARNING: Test execution timed out after ${TEST_TIMEOUT}s"
fi

end_time=$(date +%s)
duration=$((end_time - start_time))

# ---- Step 7: Collect reports ----
log "Collecting reports..."
for mod in $(echo "$MODULES" | tr ',' ' '); do
    mod_dir="${PROJECT_ROOT}/${mod}/target"
    mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')

    if [ -d "${mod_dir}/surefire-reports" ]; then
        mkdir -p "${run_dir}/${mod_name}/surefire"
        cp -r "${mod_dir}/surefire-reports/"* "${run_dir}/${mod_name}/surefire/" 2>/dev/null || true
    fi

    if [ -d "${mod_dir}/site/jacoco" ] && [ "$WITH_JACOCO" = true ]; then
        mkdir -p "${run_dir}/${mod_name}/jacoco"
        cp -r "${mod_dir}/site/jacoco/"* "${run_dir}/${mod_name}/jacoco/" 2>/dev/null || true
    fi

    if [ -d "${mod_dir}/pit-reports" ] && [ "$WITH_PIT" = true ]; then
        mkdir -p "${run_dir}/${mod_name}/pit"
        cp -r "${mod_dir}/pit-reports/"* "${run_dir}/${mod_name}/pit/" 2>/dev/null || true
    fi
done

# ---- Step 8: Stop infrastructure ----
stop_infrastructure

# ---- Step 9: Generate summary ----
{
    echo "============================================================"
    echo "AstralLight Test Run Summary"
    echo "============================================================"
    echo "Timestamp:    $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Duration:     ${duration}s ($((duration / 60))m $((duration % 60))s)"
    echo "Exit Code:    ${exit_code}"
    echo "Modules:      ${MODULES}"
    echo "JaCoCo:       ${WITH_JACOCO}"
    echo "PIT:          ${WITH_PIT}"
    echo ""

    for mod in $(echo "$MODULES" | tr ',' ' '); do
        mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
        surefire_dir="${run_dir}/${mod_name}/surefire"

        echo "---- ${mod} ----"
        if [ -d "$surefire_dir" ]; then
            total_tests=0; total_failures=0; total_errors=0; total_skipped=0
            for xml_file in "${surefire_dir}"/*.xml; do
                if [ -f "$xml_file" ]; then
                    total_tests=$((total_tests + $(grep -oP 'tests="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                    total_failures=$((total_failures + $(grep -oP 'failures="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                    total_errors=$((total_errors + $(grep -oP 'errors="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                    total_skipped=$((total_skipped + $(grep -oP 'skipped="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                fi
            done
            pass_rate="N/A"
            if [ $total_tests -gt 0 ]; then
                pass_rate="$(awk "BEGIN {printf \"%.1f%%\", (${total_tests}-${total_failures}-${total_errors})/${total_tests}*100}")"
            fi
            echo "  Tests:    ${total_tests}"
            echo "  Failures: ${total_failures}"
            echo "  Errors:   ${total_errors}"
            echo "  Skipped:  ${total_skipped}"
            echo "  Pass Rate: ${pass_rate}"
        else
            echo "  No Surefire reports found"
        fi
        echo ""
    done

    if [ "$WITH_JACOCO" = true ]; then
        echo "---- JaCoCo Coverage ----"
        for mod in $(echo "$MODULES" | tr ',' ' '); do
            mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
            jacoco_csv="${run_dir}/${mod_name}/jacoco/jacoco.csv"
            if [ -f "$jacoco_csv" ]; then
                echo "  ${mod}:"
                awk -F',' 'NR>1 {printf "    %s: %s/%s lines (%.1f%%)\n", $3, $11, $10, ($11/$10)*100}' "$jacoco_csv" 2>/dev/null || echo "    (parse error)"
            else
                echo "  ${mod}: No JaCoCo report"
            fi
        done
    fi
} > "${run_dir}/summary.txt"

# ---- Final output ----
echo ""
log "============================================================"
log "Test run complete"
log "  Duration:      ${duration}s ($((duration / 60))m $((duration % 60))s)"
log "  Exit:          ${exit_code}"
log "  Reports:       ${run_dir}/"
log "  Summary:       ${run_dir}/summary.txt"
log "  Console log:   ${run_dir}/console.log"
log "============================================================"

cat "${run_dir}/summary.txt"

exit $exit_code
