#!/bin/bash
# =============================================================================
# AstralLight 单元测试 + 集成测试
# 用法:
#   bash scripts/run-unit-integration-tests.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PROJECT_DIR="${REPO_DIR}/evaluation/benchmark-java"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="$PROJECT_DIR/test-results/$TIMESTAMP"
PHASE_LOG="$RESULTS_DIR/phases.log"

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
    local error_count

    pass_count=$(grep -c "Tests run:.*Failures: 0, Errors: 0" "$log_file" 2>/dev/null || echo 0)
    fail_count=$(grep -c "FAILURE!" "$log_file" 2>/dev/null || echo 0)
    error_count=$(grep -c "<<< ERROR" "$log_file" 2>/dev/null || echo 0)

    echo "  ┌─────────────────────────────────────────────────────" | tee -a "$PHASE_LOG"
    echo "  │ $phase_name" | tee -a "$PHASE_LOG"
    echo "  │   Passed classes: $pass_count" | tee -a "$PHASE_LOG"
    echo "  │   Failures:       $fail_count" | tee -a "$PHASE_LOG"
    echo "  │   Errors:         $error_count" | tee -a "$PHASE_LOG"
    if [ -f "$log_file" ]; then
        echo "  │   Log:            $log_file" | tee -a "$PHASE_LOG"
    fi
    echo "  └─────────────────────────────────────────────────────" | tee -a "$PHASE_LOG"
}

cd "$PROJECT_DIR"

# =============================================================================
# Phase 0: Environment check
# =============================================================================
phase "0" "ENVIRONMENT CHECK"

echo "  Project: $PROJECT_DIR" | tee -a "$PHASE_LOG"
echo "  Results: $RESULTS_DIR" | tee -a "$PHASE_LOG"

if ! docker info >/dev/null 2>&1; then
    echo "  ERROR: Docker not available." | tee -a "$PHASE_LOG"
    exit 1
fi
echo "  [OK] Docker is available" | tee -a "$PHASE_LOG"

if ! docker ps --format '{{.Names}}' | grep -q '^astral_test_mysql$'; then
    echo "  Starting test containers via docker-compose..." | tee -a "$PHASE_LOG"
    docker compose -f AstralGeneral/src/test/resources/container/docker-compose-test.yml up -d 2>&1 | tee -a "$PHASE_LOG"
    echo "  Waiting for containers to be healthy..." | tee -a "$PHASE_LOG"
    sleep 10
fi

for svc in "astral_test_mysql:3307" "astral_test_redis:6380" "astral_test_opa:8181"; do
    name="${svc%%:*}"
    port="${svc##*:}"
    if docker ps --format '{{.Names}}' | grep -q "^$name$"; then
        echo "  [OK] $name (port $port)" | tee -a "$PHASE_LOG"
    else
        echo "  [WARN] $name is NOT running" | tee -a "$PHASE_LOG"
    fi
done

# =============================================================================
# Phase 1: Compile
# =============================================================================
phase "1" "COMPILE"

mvn clean compile -DskipTests -q 2>&1 | tee "$RESULTS_DIR/compile.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "  ERROR: Compilation failed" | tee -a "$PHASE_LOG"
    exit 1
fi
echo "  [OK] Compilation successful" | tee -a "$PHASE_LOG"

# =============================================================================
# Phase 2: Unit + Integration Tests
# =============================================================================
phase "2" "UNIT & INTEGRATION TESTS (mvn test)"

mvn test -Dremote.test=true -Dmaven.test.failure.ignore=true \
    2>&1 | tee "$RESULTS_DIR/mvn-test.log"

TEST_EXIT_CODE=${PIPESTATUS[0]}

summary "Unit & Integration Tests" "$RESULTS_DIR/mvn-test.log"

if [ "$TEST_EXIT_CODE" -ne 0 ]; then
    echo "  [WARN] Some tests failed/errored (exit code: $TEST_EXIT_CODE)" | tee -a "$PHASE_LOG"
    echo "  See: $RESULTS_DIR/mvn-test.log" | tee -a "$PHASE_LOG"
else
    echo "  [OK] All tests passed" | tee -a "$PHASE_LOG"
fi

# =============================================================================
# Phase 2a: Test summary extraction
# =============================================================================
phase "2a" "TEST RESULT EXTRACTION"

grep -E "^Tests run:" "$RESULTS_DIR/mvn-test.log" \
    | tail -1 > "$RESULTS_DIR/test-total.txt" 2>/dev/null || true

grep -E "<<< FAILURE!|<<< ERROR" "$RESULTS_DIR/mvn-test.log" \
    > "$RESULTS_DIR/test-failures.txt" 2>/dev/null || true

if [ -s "$RESULTS_DIR/test-failures.txt" ]; then
    FAIL_COUNT=$(wc -l < "$RESULTS_DIR/test-failures.txt")
    echo "  Test failures/errors: $FAIL_COUNT" | tee -a "$PHASE_LOG"
    echo "  Failure details saved to: $RESULTS_DIR/test-failures.txt" | tee -a "$PHASE_LOG"
else
    echo "  [OK] No test failures" | tee -a "$PHASE_LOG"
fi

# =============================================================================
# Final Summary
# =============================================================================
phase "FINAL" "UNIT & INTEGRATION TESTS COMPLETE"

sleep 2

echo "" | tee -a "$PHASE_LOG"
echo "╔═══════════════════════════════════════════════════════════╗" | tee -a "$PHASE_LOG"
echo "║         AstralLight — UNIT & INTEGRATION TESTS           ║" | tee -a "$PHASE_LOG"
echo "╠═══════════════════════════════════════════════════════════╣" | tee -a "$PHASE_LOG"
echo "║  Results directory:" | tee -a "$PHASE_LOG"
echo "║    $RESULTS_DIR" | tee -a "$PHASE_LOG"
echo "║" | tee -a "$PHASE_LOG"

if [ -f "$RESULTS_DIR/mvn-test.log" ]; then
    TOTAL_TESTS=$(grep -oP 'Tests run: \K\d+' "$RESULTS_DIR/mvn-test.log" | paste -sd+ | bc 2>/dev/null || echo "?")
    TOTAL_FAILURES=$(grep -oP 'Failures: \K\d+' "$RESULTS_DIR/mvn-test.log" | paste -sd+ | bc 2>/dev/null || echo "?")
    TOTAL_ERRORS=$(grep -oP 'Errors: \K\d+' "$RESULTS_DIR/mvn-test.log" | paste -sd+ | bc 2>/dev/null || echo "?")
    echo "║  Tests: $TOTAL_TESTS total, $TOTAL_FAILURES failures, $TOTAL_ERRORS errors" | tee -a "$PHASE_LOG"
fi

echo "║" | tee -a "$PHASE_LOG"
echo "║  Generated files:" | tee -a "$PHASE_LOG"
for f in "$RESULTS_DIR"/*.log "$RESULTS_DIR"/*.txt; do
    [ -f "$f" ] && echo "║    - $(basename "$f")" | tee -a "$PHASE_LOG"
done

echo "╚═══════════════════════════════════════════════════════════╝" | tee -a "$PHASE_LOG"
