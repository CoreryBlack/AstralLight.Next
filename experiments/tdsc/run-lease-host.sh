#!/usr/bin/env bash
set -euo pipefail

# Host-side orchestrator for the deterministic two-worker lease experiment.
# The probe stays inside the isolated Compose network. This process alone starts
# worker B after worker A has acknowledged a successful post-claim pause.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"
RESULT_DIR="${TDSC_RESULT_DIR:?}"
COMPOSE_PROJECT="${TDSC_COMPOSE_PROJECT:?}"
WAIT_SECONDS="${TDSC_LEASE_STAGE_TIMEOUT_SECONDS:-120}"
PROBE_LOG="$(mktemp)"
STAGE_FILE="${RESULT_DIR}/lease-stage.txt"
ACK_FILE="${RESULT_DIR}/lease-ack.txt"

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
  rm -f "${PROBE_LOG}"
  exit "${exit_code}"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$*" >&2
  printf 'abort\n' > "${STAGE_FILE}"
  exit 1
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
      wait "${probe_pid}" || fail 'The in-network lease probe exited before the expected acknowledgement.'
      fail 'The in-network lease probe exited before the expected acknowledgement.'
    fi
    sleep 1
  done
  fail "Timed out waiting for lease-probe acknowledgement ${expected}."
}

cp "${SCRIPT_DIR}/run-lease-probe.sh" "${RESULT_DIR}/run-lease-probe.sh"
docker compose --project-name "${COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
  --profile workload --profile multi-node run --rm \
  -v "${RESULT_DIR}/run-lease-probe.sh:/usr/local/bin/run-lease-probe:ro" \
  -e "TDSC_LEASE_STAGE_FILE=/evidence/lease-stage.txt" \
  -e "TDSC_LEASE_ACK_FILE=/evidence/lease-ack.txt" \
  -e "TDSC_LEASE_STAGE_TIMEOUT_SECONDS=${WAIT_SECONDS}" \
  --entrypoint /usr/local/bin/run-lease-probe \
  protocol-runner > "${PROBE_LOG}" 2>&1 &
probe_pid=$!

wait_for_ack 'worker-a-claimed'

docker compose --project-name "${COMPOSE_PROJECT}" --file "${COMPOSE_FILE}" \
  --profile workload --profile multi-node --profile lease-worker-b \
  up --detach --wait --wait-timeout "${TDSC_WAIT_TIMEOUT_SECONDS:-240}" identity-worker-b
write_stage 'worker-b-started'

wait_for_ack 'complete'
wait "${probe_pid}"
probe_pid=""
