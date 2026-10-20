#!/usr/bin/env bash
set -euo pipefail

# Host-side controller for the TDSC in-network fault probe. Docker lifecycle
# operations stay here; the probe receives stage changes and returns
# acknowledgements only through /evidence marker files. Marker contents are
# fixed stage names and never include credentials, tokens, endpoints, or IDs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"
RESULT_DIR="${TDSC_RESULT_DIR:?}"
COMPOSE_PROJECT="${TDSC_COMPOSE_PROJECT:?}"
WAIT_SECONDS="${TDSC_FAULT_STAGE_TIMEOUT_SECONDS:-90}"
PROBE_LOG="$(mktemp)"
STAGE_FILE="${RESULT_DIR}/fault-stage.txt"
ACK_FILE="${RESULT_DIR}/fault-ack.txt"

mkdir -p "${RESULT_DIR}"
: > "${STAGE_FILE}"
: > "${ACK_FILE}"

probe_pid=""
cleanup() {
  local exit_code=$?
  if [[ -n "${probe_pid}" ]] && kill -0 "${probe_pid}" >/dev/null 2>&1; then
    kill "${probe_pid}" >/dev/null 2>&1 || true
    wait "${probe_pid}" >/dev/null 2>&1 || true
  fi
  if [[ "$(redis_container_id)" != "" ]]; then
    docker unpause "$(redis_container_id)" >/dev/null 2>&1 || true
  fi
  if [[ "$(mysql_container_id)" != "" ]]; then
    docker unpause "$(mysql_container_id)" >/dev/null 2>&1 || true
  fi
  rm -f "${PROBE_LOG}"
  exit "${exit_code}"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$*" >&2
  printf 'abort\n' > "${STAGE_FILE}"
  exit 1
}

redis_container_id() {
  docker ps --all \
    --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
    --filter 'label=com.docker.compose.service=redis' \
    --format '{{.ID}}' | head -n 1
}

mysql_container_id() {
  docker ps --all \
    --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
    --filter 'label=com.docker.compose.service=mysql' \
    --format '{{.ID}}' | head -n 1
}

require_redis_container() {
  local container_id
  container_id="$(redis_container_id)"
  [[ -n "${container_id}" ]] || fail 'Unable to find the Redis service container for this Compose project.'
  printf '%s\n' "${container_id}"
}

require_mysql_container() {
  local container_id
  container_id="$(mysql_container_id)"
  [[ -n "${container_id}" ]] || fail 'Unable to find the MySQL service container for this Compose project.'
  printf '%s\n' "${container_id}"
}

write_stage() {
  local stage="$1"
  local temporary="${STAGE_FILE}.tmp.$$"
  printf '%s\n' "${stage}" > "${temporary}"
  mv "${temporary}" "${STAGE_FILE}"
}

wait_for_ack() {
  local expected="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local actual=""
  while (( SECONDS < deadline )); do
    if [[ -f "${ACK_FILE}" ]]; then
      actual="$(<"${ACK_FILE}")"
      if [[ "${actual}" == "${expected}" ]]; then
        return 0
      fi
    fi
    if [[ -n "${probe_pid}" ]] && ! kill -0 "${probe_pid}" >/dev/null 2>&1; then
      wait "${probe_pid}" || fail 'The in-network fault probe exited before acknowledging the requested stage.'
      fail 'The in-network fault probe exited before acknowledging the requested stage.'
    fi
    sleep 1
  done
  fail "Timed out waiting for fault-probe acknowledgement ${expected}."
}

# The command remains a normal Compose-run process. The mounted probe script is
# copied into the run directory for input retention, while evidence stays in the
# run-scoped host bind mount defined by compose.yml.
cp "${SCRIPT_DIR}/run-fault.sh" "${RESULT_DIR}/run-fault.sh"
docker compose --project-name "${COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
  --profile workload run --rm \
  -v "${RESULT_DIR}/run-fault.sh:/usr/local/bin/run-fault:ro" \
  -e "TDSC_FAULT_STAGE_FILE=/evidence/fault-stage.txt" \
  -e "TDSC_FAULT_ACK_FILE=/evidence/fault-ack.txt" \
  -e "TDSC_FAULT_STAGE_TIMEOUT_SECONDS=${WAIT_SECONDS}" \
  --entrypoint /usr/local/bin/run-fault \
  protocol-runner > "${PROBE_LOG}" 2>&1 &
probe_pid=$!

wait_for_ack 'ready'
redis_id="$(require_redis_container)"
docker pause "${redis_id}" > /dev/null
write_stage 'redis-paused'
wait_for_ack 'f1-paused-recorded'

docker unpause "${redis_id}" > /dev/null
write_stage 'redis-resumed'
wait_for_ack 'f1-resumed-recorded'

redis_id="$(require_redis_container)"
docker restart "${redis_id}" > /dev/null
write_stage 'redis-restarted'
wait_for_ack 'f2-restarted-recorded'

wait_for_ack 'f3-fixture-ready'
mysql_id="$(require_mysql_container)"
docker pause "${mysql_id}" > /dev/null
write_stage 'mysql-paused'
wait_for_ack 'f3-paused-recorded'

docker unpause "${mysql_id}" > /dev/null
write_stage 'mysql-resumed'
wait_for_ack 'f3-resumed-recorded'
wait_for_ack 'complete'

wait "${probe_pid}"
probe_pid=""
