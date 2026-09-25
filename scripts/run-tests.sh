#!/usr/bin/env bash
# AstralLight-Rust 测试运行脚本
#
# 用法:
#   ./scripts/run-tests.sh                 # 启动隔离 Docker 环境 + 单元测试
#   ./scripts/run-tests.sh --integration   # 严格真实集成 gate（含单元测试）
#   ./scripts/run-tests.sh --full          # --integration 的兼容别名
#   ./scripts/run-tests.sh --check         # cargo check + clippy
#   ./scripts/run-tests.sh --bench         # cargo bench
#
# 集成 gate 必须使用 docker-compose.test.yml 的隔离端口，并由调用方显式提供
# MySQL/RabbitMQ 凭据、连接 URL、ASTRAL_MIGRATION_ENV=isolated 和
# RUST_INTEGRATION_REQUIRED=1。SKIP_DOCKER 只允许用于 unit 模式，不能让
# --integration/--full 在 Docker 不可用时变成绿色 skip。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

COMPOSE_FILE="docker-compose.test.yml"
DOCKER_STARTED=0

fail() {
    printf '[error] %s\n' "$1" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_test_environment() {
    : "${DATABASE_URL:?DATABASE_URL is required}"
    : "${REDIS_URL:?REDIS_URL is required}"
    : "${RABBITMQ_URL:?RABBITMQ_URL is required}"
    if [ "${SKIP_DOCKER:-0}" != "1" ]; then
        : "${MYSQL_ROOT_PASSWORD:?MYSQL_ROOT_PASSWORD is required}"
        : "${MYSQL_DATABASE:?MYSQL_DATABASE is required}"
        : "${RABBITMQ_USER:?RABBITMQ_USER is required}"
        : "${RABBITMQ_PASSWORD:?RABBITMQ_PASSWORD is required}"
    fi
}

require_integration_environment() {
    [ "${SKIP_DOCKER:-0}" != "1" ] || fail "SKIP_DOCKER=1 is forbidden for the real integration gate"
    : "${MYSQL_ROOT_PASSWORD:?MYSQL_ROOT_PASSWORD is required for the isolated gate}"
    : "${MYSQL_DATABASE:?MYSQL_DATABASE is required for the isolated gate}"
    : "${RABBITMQ_USER:?RABBITMQ_USER is required for the isolated gate}"
    : "${RABBITMQ_PASSWORD:?RABBITMQ_PASSWORD is required for the isolated gate}"
    : "${DATABASE_URL:?DATABASE_URL is required for the isolated gate}"
    : "${REDIS_URL:?REDIS_URL is required for the isolated gate}"
    : "${RABBITMQ_URL:?RABBITMQ_URL is required for the isolated gate}"
    : "${ASTRAL_MIGRATION_ENV:?ASTRAL_MIGRATION_ENV is required for the isolated gate}"
    : "${RUST_INTEGRATION_REQUIRED:?RUST_INTEGRATION_REQUIRED is required for the isolated gate}"
    [ "$ASTRAL_MIGRATION_ENV" = "isolated" ] || fail "ASTRAL_MIGRATION_ENV must be isolated"
    [ "$RUST_INTEGRATION_REQUIRED" = "1" ] || fail "RUST_INTEGRATION_REQUIRED must be 1"

    case "$DATABASE_URL" in
        mysql://*@localhost:3308/*|mysql://*@127.0.0.1:3308/*) ;;
        *) fail "DATABASE_URL must target the docker-compose.test.yml MySQL port 3308" ;;
    esac
    case "$REDIS_URL" in
        redis://localhost:6380*|redis://127.0.0.1:6380*) ;;
        *) fail "REDIS_URL must target the docker-compose.test.yml Redis port 6380" ;;
    esac
    case "$RABBITMQ_URL" in
        amqp://*@localhost:5673/*|amqp://*@127.0.0.1:5673/*) ;;
        *) fail "RABBITMQ_URL must target the docker-compose.test.yml RabbitMQ port 5673" ;;
    esac
}

require_docker() {
    require_command docker
    docker compose version >/dev/null 2>&1 || fail "Docker Compose is unavailable"
    docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable; integration gate stopped"
}

MODE="${1:-unit}"

start_docker() {
    if [ "${SKIP_DOCKER:-0}" = "1" ]; then
        printf '[skip] Docker 已由调用方管理，当前仅 unit 模式跳过启动\n'
        return
    fi
    require_docker
    printf '[docker] 启动隔离集成测试环境...\n'
    docker compose -f "$COMPOSE_FILE" config --quiet
    # Mark the stack for cleanup before `up`; a partial startup must not be left
    # behind when Docker exits non-zero.
    DOCKER_STARTED=1
    docker compose -f "$COMPOSE_FILE" up -d --wait
    printf '[docker] 环境就绪: MySQL(3308) Redis(6380) RabbitMQ(5673)\n'
}

start_rust_migrations() {
    printf '[migration] applying isolated Rust-owned migrations...\n'
    ASTRAL_MIGRATION_ENV=isolated cargo run -p astral-db --bin astral-migrate -- --apply
}

stop_docker() {
    if [ "$DOCKER_STARTED" != "1" ]; then
        return
    fi
    printf '[docker] 停止隔离集成测试环境...\n'
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans || true
}

run_integration_gate() {
    require_integration_environment
    start_docker
    start_rust_migrations
    printf '[cargo] 单元测试\n'
    cargo test --workspace --lib
    printf '[cargo] 真实集成测试（ignored；缺依赖或连接失败必须失败）\n'
    cargo test --workspace --test '*' -- --ignored --nocapture --test-threads=1
}

trap stop_docker EXIT

case "$MODE" in
    --check)
        printf '[cargo] check + clippy\n'
        cargo check --workspace --all-targets
        cargo clippy --workspace --all-targets -- -D warnings
        ;;
    --integration|--full)
        run_integration_gate
        ;;
    --bench)
        printf '[cargo] benchmark\n'
        cargo bench --workspace
        ;;
    unit|--unit|"")
        require_test_environment
        start_docker
        start_rust_migrations
        printf '[cargo] 单元测试\n'
        cargo test --workspace --lib
        ;;
    *)
        printf '用法: %s [--integration|--full|--check|--bench|unit]\n' "$0" >&2
        exit 1
        ;;
esac

printf '[done] 完成\n'
