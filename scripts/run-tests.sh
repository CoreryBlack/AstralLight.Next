#!/usr/bin/env bash
# Default gate: MySQL + local transport. Rabbit and Redis adapters are opt-in.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"
MODE="${1:-unit}"
RUN_ID="${RUN_ID:-astral-test-$(date +%Y%m%d%H%M%S)-$$}"
case "$RUN_ID" in
    *[!a-zA-Z0-9_-]*|"") printf '[error] invalid RUN_ID\n' >&2; exit 1 ;;
esac
unset COMPOSE_PROFILES
COMPOSE=(docker compose -p "astral-test-${RUN_ID}" -f docker-compose.test.yml)
DOCKER_STARTED=0
FAILED=0

fail() { printf '[error] %s\n' "$1" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "required command unavailable: $1"; }
require_command cargo
require_command timeout
LOG_DIR="${TEST_ARTIFACT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/${RUN_ID}.XXXXXX")}"
mkdir -p "$LOG_DIR"
printf '[evidence] run=%s cwd=%s logs=%s\n' "$RUN_ID" "$PROJECT_DIR" "$LOG_DIR"
PHASE_SECONDS="${TEST_PHASE_TIMEOUT_SECONDS:-1800}"
case "$PHASE_SECONDS" in *[!0-9]*|""|0) fail 'TEST_PHASE_TIMEOUT_SECONDS must be positive' ;; esac

phase() {
    local name="$1" code=0
    shift
    printf '[phase] %s command=' "$name"
    printf '%q ' "$@"
    printf '\n'
    local started=$SECONDS
    if timeout --kill-after=15s "${PHASE_SECONDS}s" "$@" >"$LOG_DIR/$name.log" 2>&1; then
        code=0
    else
        code=$?
    fi
    printf '[phase] %s exit=%s elapsed=%ss log=%s\n' "$name" "$code" "$((SECONDS - started))" "$LOG_DIR/$name.log"
    if [ "$code" = 124 ] || [ "$code" = 137 ]; then
        printf '[UNKNOWN] %s timed out; reconcile before retry\n' "$name" >&2
        return "$code"
    elif [ "$code" != 0 ]; then
        printf '[FAIL] %s\n' "$name" >&2
    elif grep -Eq '\[(SKIP|skip)\]' "$LOG_DIR/$name.log"; then
        printf '[SKIP] %s contains unexecuted checks; not PASS\n' "$name" >&2
        code=1
    else
        printf '[PASS] %s\n' "$name"
    fi
    grep 'test result:' "$LOG_DIR/$name.log" || true
    return "$code"
}

test_phase() {
    local code=0
    phase "$@" || code=$?
    if [ "$code" = 124 ] || [ "$code" = 137 ]; then exit "$code"; fi
    if [ "$code" != 0 ]; then FAILED=1; fi
}

stop_docker() {
    if [ "$DOCKER_STARTED" = 1 ]; then
        if ! phase compose-down "${COMPOSE[@]}" down --volumes; then
            printf '[UNKNOWN] test resource cleanup failed\n' >&2
            return 1
        fi
    fi
}
finish() {
    local code=$?
    trap - EXIT
    if ! stop_docker; then code=1; fi
    printf '[evidence] final_exit=%s logs=%s\n' "$code" "$LOG_DIR"
    exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_database() {
    [ "${SKIP_DOCKER:-0}" != 1 ] || fail 'SKIP_DOCKER is retired; use TEST_USE_EXISTING=1 with a migrated isolated database'
    : "${DATABASE_URL:?DATABASE_URL is required}"
    : "${ASTRAL_MIGRATION_ENV:?ASTRAL_MIGRATION_ENV is required}"
    [ "$ASTRAL_MIGRATION_ENV" = isolated ] || fail 'ASTRAL_MIGRATION_ENV must be isolated'
    : "${RUST_INTEGRATION_REQUIRED:?RUST_INTEGRATION_REQUIRED is required}"
    [ "$RUST_INTEGRATION_REQUIRED" = 1 ] || fail 'RUST_INTEGRATION_REQUIRED must be 1'
    case "$DATABASE_URL" in
        mysql://*@localhost:3308/astral_test|mysql://*@127.0.0.1:3308/astral_test|mysql://*@localhost:3308/astral_rehearsal|mysql://*@127.0.0.1:3308/astral_rehearsal) ;;
        *) fail 'DATABASE_URL must select astral_test/astral_rehearsal on loopback port 3308' ;;
    esac
}

start_environment() {
    require_database
    case "${TEST_USE_EXISTING:-0}" in
        1) printf '[environment] existing isolated database; no Docker startup or DDL\n'; return ;;
        0) ;;
        *) fail 'TEST_USE_EXISTING must be 0 or 1' ;;
    esac
    : "${MYSQL_ROOT_PASSWORD:?MYSQL_ROOT_PASSWORD is required}"
    : "${MYSQL_DATABASE:?MYSQL_DATABASE is required}"
    case "$MYSQL_DATABASE" in astral_test|astral_rehearsal) ;; *) fail 'invalid isolated MYSQL_DATABASE' ;; esac
    [ "${DATABASE_URL##*/}" = "$MYSQL_DATABASE" ] || fail 'MYSQL_DATABASE and DATABASE_URL disagree'
    require_command docker
    phase docker-preflight docker info
    phase compose-preflight "${COMPOSE[@]}" config --quiet
    phase compose-ownership "${COMPOSE[@]}" ps -a -q
    [ ! -s "$LOG_DIR/compose-ownership.log" ] || fail 'compose project already exists; use a fresh RUN_ID or TEST_USE_EXISTING=1'
    DOCKER_STARTED=1
    phase compose-up "${COMPOSE[@]}" up -d --wait --wait-timeout 180
    # The production migrator retains its destructive allowlist/proof gates.
    phase migrations cargo run -p astral-db --bin astral-migrate -- --apply
}

run_tenant_tests() {
    local target
    for target in mt_extreme_capacity mt_extreme_churn mt_extreme_cross_storm mt_extreme_failclosed mt_extreme_isolation; do
        test_phase "$target" cargo test -p testsuite --test "$target" -- --ignored --nocapture --test-threads=1
    done
}

run_mysql_tests() {
    local target
    for target in authorization_projection_integration integration multi_tenant_isolation org_scope_integration partition_lease_integration quarantine_integration; do
        test_phase "db-$target" cargo test -p astral-db --test "$target" --no-fail-fast -- --ignored --nocapture --test-threads=1
    done
    test_phase identity cargo test -p astral-identity --test integration -- --ignored --nocapture --test-threads=1
    test_phase monitor cargo test -p astral-monitor --test integration -- --ignored --nocapture --test-threads=1
    test_phase trustgraph cargo test -p astral-trustgraph --test integration --test org_scope_projector_integration --no-fail-fast -- --ignored --nocapture --test-threads=1
    run_tenant_tests
    test_phase hub-invalidation cargo test -p testsuite --test premise_hub_invalidation -- --ignored --nocapture --test-threads=1
    test_phase writer-lease cargo test -p testsuite --test premise_single_writer_lease -- --ignored --nocapture --test-threads=1
    test_phase mapping-premise cargo test -p testsuite --test premise_identity_mapping -- --ignored --nocapture --test-threads=1
    printf '[scope] dedicated identity mapping, Rabbit, Redis compat and ignored CPU benchmarks are separate gates\n'
}

case "$MODE" in
    --redis-compat)
        : "${REDIS_URL:?REDIS_URL is required only for --redis-compat}"
        case "$REDIS_URL" in redis://localhost:6380/*|redis://127.0.0.1:6380/*) ;; *) fail 'compat Redis must use loopback port 6380' ;; esac
        export ASTRAL_REDIS_PROJECTION_COMPAT=true ASTRAL_MESSAGE_TRANSPORT=local
        COMPOSE+=(--profile redis-compat)
        start_environment
        test_phase redis-compat cargo test -p astral-db --features redis-compat --test evidence_cache_redis_integration -- --ignored --nocapture --test-threads=1
        ;;
    --identity-mapping)
        unset REDIS_URL
        export ASTRAL_REDIS_PROJECTION_COMPAT=false ASTRAL_MESSAGE_TRANSPORT=local
        : "${DATABASE_URL:?pre-migrated dedicated DATABASE_URL is required}"
        : "${INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE:?dedicated database name is required}"
        [ "${RUST_INTEGRATION_REQUIRED:-}" = 1 ] || fail 'RUST_INTEGRATION_REQUIRED must be 1'
        printf '[environment] dedicated pre-migrated database; no Docker startup or DDL\n'
        test_phase identity-mapping cargo test -p astral-db --test integration_identity_mapping -- --ignored --nocapture --test-threads=1
        ;;
    unit|--unit|--check|--bench|--integration|--full|--mt-extreme|--mt-matrix|--rabbit)
        unset REDIS_URL
        export ASTRAL_REDIS_PROJECTION_COMPAT=false ASTRAL_MESSAGE_TRANSPORT=local
        case "$MODE" in
            unit|--unit)
                test_phase unit env -u DATABASE_URL -u RABBITMQ_URL -u RUST_INTEGRATION_REQUIRED cargo test --workspace --no-fail-fast
                ;;
            --check)
                test_phase check cargo check --workspace --all-targets
                test_phase clippy cargo clippy --workspace --all-targets -- -D warnings
                ;;
            --bench) test_phase bench cargo bench --workspace ;;
            --rabbit)
                : "${RABBITMQ_URL:?RABBITMQ_URL is required only for --rabbit}"
                case "$RABBITMQ_URL" in amqp://*@localhost:5673/?*|amqp://*@127.0.0.1:5673/?*) ;; *) fail 'Rabbit must use loopback port 5673 and an explicit vhost path (%2f for /)' ;; esac
                if [ "${TEST_USE_EXISTING:-0}" != 1 ]; then
                    : "${RABBITMQ_USER:?RABBITMQ_USER is required}"
                    : "${RABBITMQ_PASSWORD:?RABBITMQ_PASSWORD is required}"
                fi
                export ASTRAL_MESSAGE_TRANSPORT=rabbit
                COMPOSE+=(--profile rabbit)
                start_environment
                test_phase audit-replay cargo test -p astral-trustgraph --test audit_replay_integration -- --ignored --nocapture --test-threads=1
                ;;
            --integration|--full)
                start_environment
                run_mysql_tests
                ;;
            --mt-extreme)
                start_environment
                run_tenant_tests
                ;;
            --mt-matrix)
                start_environment
                shift
                test_phase matrix bash tests-suite/matrix/run-mt-matrix.sh "$@"
                ;;
        esac
        ;;
    *) fail 'usage: run-tests.sh [unit|--check|--integration|--mt-extreme|--mt-matrix|--rabbit|--redis-compat|--identity-mapping|--bench]' ;;
esac
exit "$FAILED"
