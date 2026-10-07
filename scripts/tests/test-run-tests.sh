#!/usr/bin/env bash
# Deterministic runner contract tests. No real Cargo, Docker or database actions.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/astral-runner-tests.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat >"$TMP/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf 'cargo %s|compat=%s|transport=%s|redis=%s|db=%s|rabbit=%s|required=%s\n' \
    "$*" "${ASTRAL_REDIS_PROJECTION_COMPAT:-unset}" "${ASTRAL_MESSAGE_TRANSPORT:-unset}" \
    "${REDIS_URL:-unset}" "${DATABASE_URL:-unset}" "${RABBITMQ_URL:-unset}" \
    "${RUST_INTEGRATION_REQUIRED:-unset}" >>"$TRACE"
if [ "${MOCK_CARGO_DELAY:-0}" != 0 ]; then sleep "$MOCK_CARGO_DELAY"; fi
if [ "${MOCK_SKIP:-0}" = 1 ]; then printf '[SKIP] mock unavailable dependency\n'; fi
exit "${MOCK_CARGO_EXIT:-0}"
STUB
cat >"$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >>"$TRACE"
if [[ "$*" == *'ps -a -q'* ]] && [ "${MOCK_EXISTING_PROJECT:-0}" = 1 ]; then printf 'existing-container\n'; fi
if [[ "$*" == *'up -d'* ]]; then exit "${MOCK_DOCKER_UP_EXIT:-0}"; fi
exit 0
STUB
chmod +x "$TMP/bin/cargo" "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH"
export RUN_ID=runner-contract
export TRACE="$TMP/trace"
unset MYSQL_ROOT_PASSWORD MYSQL_DATABASE RABBITMQ_USER RABBITMQ_PASSWORD DATABASE_URL REDIS_URL RABBITMQ_URL
unset ASTRAL_MIGRATION_ENV RUST_INTEGRATION_REQUIRED SKIP_DOCKER TEST_USE_EXISTING COMPOSE_PROFILES
unset ASTRAL_DESTRUCTIVE_MIGRATION_ALLOWLIST ASTRAL_DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ID ASTRAL_DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ID ASTRAL_DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ID

run() {
    : >"$TRACE"
    export TEST_ARTIFACT_DIR="$TMP/logs-$1"
    shift
    RESULT=0
    bash "$ROOT/scripts/run-tests.sh" "$@" >"$TMP/output" 2>&1 || RESULT=$?
}
assert_has() { grep -F -- "$2" "$1" >/dev/null || { printf 'missing: %s\n' "$2" >&2; exit 1; }; }
assert_lacks() { if grep -F -- "$2" "$1" >/dev/null; then printf 'unexpected: %s\n' "$2" >&2; exit 1; fi; }

run unit unit
[ "$RESULT" = 0 ]
assert_has "$TRACE" 'test --workspace --no-fail-fast'
assert_has "$TRACE" 'compat=false|transport=local|redis=unset|db=unset|rabbit=unset|required=unset'
assert_lacks "$TRACE" docker

export DATABASE_URL=mysql://fixture@127.0.0.1:3308/astral_test
export ASTRAL_MIGRATION_ENV=isolated RUST_INTEGRATION_REQUIRED=1 TEST_USE_EXISTING=1
export REDIS_URL=redis://deliberately-unreachable/ RABBITMQ_URL=amqp://deliberately-unreachable/
run existing --integration
[ "$RESULT" = 0 ]
assert_has "$TRACE" '--test multi_tenant_isolation'
assert_has "$TRACE" '-p testsuite --test mt_extreme_churn'
assert_lacks "$TRACE" '--features'
assert_lacks "$TRACE" 'integration_identity_mapping'
assert_lacks "$TRACE" 'audit_replay_integration'
assert_lacks "$TRACE" 'redis-compat'
assert_lacks "$TRACE" 'cargo run'
assert_lacks "$TRACE" docker
assert_has "$TRACE" 'compat=false|transport=local|redis=unset'

export MOCK_CARGO_EXIT=101
run failure --integration
[ "$RESULT" != 0 ]
assert_has "$TMP/output" 'exit=101'
assert_has "$TRACE" '-p testsuite'
unset MOCK_CARGO_EXIT
export MOCK_SKIP=1
run skip --mt-extreme
[ "$RESULT" != 0 ]
assert_has "$TMP/output" '[SKIP]'
unset MOCK_SKIP

export TEST_PHASE_TIMEOUT_SECONDS=1 MOCK_CARGO_DELAY=3
run timeout --integration
[ "$RESULT" = 124 ]
assert_has "$TMP/output" '[UNKNOWN]'
assert_lacks "$TRACE" '-p testsuite'
unset TEST_PHASE_TIMEOUT_SECONDS MOCK_CARGO_DELAY

export TEST_USE_EXISTING=0 MYSQL_ROOT_PASSWORD=fixture MYSQL_DATABASE=astral_test
run managed --mt-extreme
[ "$RESULT" = 0 ]
assert_has "$TRACE" 'cargo run -p astral-db --bin astral-migrate -- --apply'
assert_has "$TRACE" 'down --volumes'
assert_lacks "$TRACE" '--profile'
export MOCK_DOCKER_UP_EXIT=17
run startup-fail --integration
[ "$RESULT" != 0 ]
assert_has "$TRACE" 'down --volumes'
assert_lacks "$TRACE" 'cargo run'
unset MOCK_DOCKER_UP_EXIT
export MOCK_EXISTING_PROJECT=1
run existing-project --integration
[ "$RESULT" != 0 ]
assert_lacks "$TRACE" 'up -d'
assert_lacks "$TRACE" 'down --volumes'
unset MOCK_EXISTING_PROJECT

export TEST_USE_EXISTING=1 RABBITMQ_URL=amqp://fixture@127.0.0.1:5673/
run invalid-vhost --rabbit
[ "$RESULT" != 0 ]
assert_lacks "$TRACE" 'cargo test'
export RABBITMQ_URL=amqp://fixture@127.0.0.1:5673/%2f
run rabbit --rabbit
[ "$RESULT" = 0 ]
assert_has "$TRACE" '--test audit_replay_integration'
assert_has "$TRACE" 'compat=false|transport=rabbit|redis=unset'
export REDIS_URL=redis://127.0.0.1:6380/
run compat --redis-compat
[ "$RESULT" = 0 ]
assert_has "$TRACE" '--features redis-compat --test evidence_cache_redis_integration'
assert_has "$TRACE" 'compat=true'

export TEST_ARTIFACT_DIR="$TMP/matrix"
rm -f "$TRACE"
bash "$ROOT/tests-suite/matrix/run-mt-matrix.sh" --suites 'mt_extreme_churn mt_extreme_capacity' >"$TMP/output" 2>&1
assert_has "$TRACE" '--test mt_extreme_churn'
assert_has "$TRACE" '--test mt_extreme_capacity'
assert_lacks "$TRACE" '--test *'
assert_lacks "$TRACE" '--features'
assert_has "$TRACE" 'compat=false|transport=local|redis=unset'
printf 'runner contracts: 12 scenarios passed\n'
