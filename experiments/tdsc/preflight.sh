#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

required_variables=(
  TDSC_COMPOSE_PROJECT
  TDSC_RUN_ID
  TDSC_SEED
  TDSC_MYSQL_IMAGE
  TDSC_REDIS_IMAGE
  TDSC_RABBITMQ_IMAGE
  TDSC_OPA_IMAGE
  TDSC_IDENTITY_IMAGE
  TDSC_TRUSTGRAPH_IMAGE
  TDSC_LEARN_IMAGE
  TDSC_GATEWAY_IMAGE
  TDSC_PROTOCOL_RUNNER_IMAGE
  TDSC_DB_NAME
  TDSC_DB_USERNAME
  TDSC_DB_PASSWORD
  TDSC_DB_ROOT_PASSWORD
  TDSC_RABBITMQ_USERNAME
  TDSC_RABBITMQ_PASSWORD
  TDSC_JWT_SECRET
  TDSC_SESSION_RESPONSE_AES_GCM_KEY
  TDSC_SERVICE_CPUSET
  TDSC_RUNNER_CPUSET
  TDSC_MYSQL_MEMORY_LIMIT
  TDSC_REDIS_MEMORY_LIMIT
  TDSC_RABBITMQ_MEMORY_LIMIT
  TDSC_IDENTITY_MEMORY_LIMIT
  TDSC_TRUSTGRAPH_MEMORY_LIMIT
  TDSC_LEARN_MEMORY_LIMIT
  TDSC_GATEWAY_MEMORY_LIMIT
  TDSC_RUNNER_MEMORY_LIMIT
  TDSC_OPA_MEMORY_LIMIT
)

for variable_name in "${required_variables[@]}"; do
  if [[ -z "${!variable_name:-}" ]]; then
    printf 'Missing required environment variable: %s\n' "${variable_name}" >&2
    exit 2
  fi
done

if ! [[ "${TDSC_RUN_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  printf 'TDSC_RUN_ID must contain only letters, digits, dot, underscore, or hyphen.\n' >&2
  exit 2
fi

if ! [[ "${TDSC_SEED}" =~ ^[0-9]+$ ]]; then
  printf 'TDSC_SEED must be an unsigned integer.\n' >&2
  exit 2
fi

for image_variable in \
  TDSC_MYSQL_IMAGE TDSC_REDIS_IMAGE TDSC_RABBITMQ_IMAGE TDSC_OPA_IMAGE \
  TDSC_IDENTITY_IMAGE TDSC_TRUSTGRAPH_IMAGE TDSC_LEARN_IMAGE TDSC_GATEWAY_IMAGE \
  TDSC_PROTOCOL_RUNNER_IMAGE; do
  if [[ "${!image_variable}" != *@sha256:* ]]; then
    printf '%s must be pinned by immutable image digest.\n' "${image_variable}" >&2
    exit 2
  fi
done

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf 'Docker daemon is unavailable.\n' >&2
  exit 3
fi

if ! docker compose version >/dev/null 2>&1; then
  printf 'Docker Compose v2 is required.\n' >&2
  exit 3
fi

if [[ -n "$(docker ps --all --filter "label=com.docker.compose.project=${TDSC_COMPOSE_PROJECT}" --quiet)" ]]; then
  printf 'Compose project %s already has containers; choose a new TDSC_RUN_ID.\n' "${TDSC_COMPOSE_PROJECT}" >&2
  exit 4
fi

if [[ "${TDSC_ALLOW_DIRTY_WORKTREE:-false}" != "true" ]]; then
  if [[ -n "$(git -C "${REPO_DIR}" status --porcelain)" ]]; then
    printf 'Refusing an evidence run from a dirty worktree.\n' >&2
    exit 4
  fi
fi

all_cpus="${TDSC_SERVICE_CPUSET},${TDSC_RUNNER_CPUSET}"
if [[ ! "${all_cpus}" =~ ^[0-9,-]+$ ]]; then
  printf 'CPU sets must use only CPU numbers, commas, and ranges.\n' >&2
  exit 2
fi

require_governor="${TDSC_REQUIRE_PERFORMANCE_GOVERNOR:-true}"
if [[ "${require_governor}" == "true" ]]; then
  shopt -s nullglob
  governor_files=(/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)
  shopt -u nullglob
  if (( ${#governor_files[@]} == 0 )); then
    printf 'CPU governor cannot be verified; refusing a performance evidence run.\n' >&2
    exit 4
  fi
  for governor_file in "${governor_files[@]}"; do
    if [[ "$(<"${governor_file}")" != "performance" ]]; then
      printf 'CPU governor is not performance; refusing a performance evidence run.\n' >&2
      exit 4
    fi
  done
fi

max_load_per_cpu="${TDSC_MAX_LOAD_PER_CPU:-0.25}"
if ! awk -v threshold="${max_load_per_cpu}" 'BEGIN { exit !(threshold > 0) }'; then
  printf 'TDSC_MAX_LOAD_PER_CPU must be positive.\n' >&2
  exit 2
fi

cpu_count="$(nproc)"
load_1m="$(awk '{print $1}' /proc/loadavg)"
if ! awk -v load="${load_1m}" -v cpus="${cpu_count}" -v threshold="${max_load_per_cpu}" \
  'BEGIN { exit !(load <= cpus * threshold) }'; then
  printf 'Host load exceeds the configured evidence-run limit.\n' >&2
  exit 4
fi

printf 'TDSC Docker preflight passed for run %s.\n' "${TDSC_RUN_ID}"
