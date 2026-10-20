#!/usr/bin/env bash
set -euo pipefail

# TDSC in-network fault probe.
#
# This script deliberately does not control containers. A host-side orchestrator
# applies the Redis pause, resume, and restart operations, then advances the
# marker named by TDSC_FAULT_STAGE_FILE. The probe records only the endpoint
# observations and writes acknowledgement markers below /evidence.
#
# Implemented cases:
#   F1 Redis paused during protected access: expected fail-closed 503.
#   F1 Redis resumed after protected access: expected recovery 200.
#   F2 Redis restarted with no persistence: old access token expected 401.
#   F3 MySQL paused during recover-by-key: typed 503 then same response after recovery.
#
# The probe does not claim projection crash, outbox convergence, or parallel
# recovery behavior because those faults are exercised by dedicated workloads.

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
GATEWAY_BASE_URL="${GATEWAY_BASE_URL:?}"
TDSC_RUN_ID="${TDSC_RUN_ID:?}"
TDSC_SEED="${TDSC_SEED:?}"
DB_HOST="${DB_HOST:?}"
DB_PORT="${DB_PORT:?}"
DB_NAME="${DB_NAME:?}"
DB_USERNAME="${DB_USERNAME:?}"
DB_PASSWORD="${DB_PASSWORD:?}"
STAGE_FILE="${TDSC_FAULT_STAGE_FILE:-${EVIDENCE_DIR}/fault-stage.txt}"
ACK_FILE="${TDSC_FAULT_ACK_FILE:-${EVIDENCE_DIR}/fault-ack.txt}"
WAIT_SECONDS="${TDSC_FAULT_STAGE_TIMEOUT_SECONDS:-90}"

readonly PROTECTED_PATH="/main/api/v1/permission-rules/registry"
readonly REGISTER_PATH="/api/v1/auth/register"
readonly LOGIN_PATH="/api/v1/auth/login"
readonly SWITCH_PATH="/api/v1/auth/switch-card"
readonly RECOVER_BY_KEY_PATH="/api/v1/auth/session-operations/recover-by-key"

mkdir -p "${EVIDENCE_DIR}"
WORK_DIR="$(mktemp -d)"
FAULT_CASES="${EVIDENCE_DIR}/fault-cases.jsonl"
FAULT_SUMMARY="${EVIDENCE_DIR}/fault-summary.json"
FAULT_LIMITATIONS="${EVIDENCE_DIR}/fault-limitations.json"
: > "${FAULT_CASES}"

cleanup() {
  local exit_code=$?
  rm -rf "${WORK_DIR}"
  exit "${exit_code}"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

mysql_query() {
  MYSQL_PWD="${DB_PASSWORD}" mariadb --protocol=TCP --host="${DB_HOST}" --port="${DB_PORT}" \
    --user="${DB_USERNAME}" --database="${DB_NAME}" --batch --skip-column-names --raw --execute "$1"
}

write_ack() {
  local marker="$1"
  local temp_file="${ACK_FILE}.tmp.$$"
  printf '%s\n' "${marker}" > "${temp_file}"
  mv "${temp_file}" "${ACK_FILE}"
}

wait_for_stage() {
  local expected="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local actual=""
  while (( SECONDS < deadline )); do
    if [[ -f "${STAGE_FILE}" ]]; then
      actual="$(<"${STAGE_FILE}")"
      if [[ "${actual}" == "${expected}" ]]; then
        return 0
      fi
      if [[ "${actual}" == "abort" ]]; then
        fail 'Host fault orchestrator aborted the probe.'
      fi
    fi
    sleep 1
  done
  fail "Timed out waiting for fault stage ${expected}."
}

record_fault_case() {
  local case_id="$1"
  local stage="$2"
  local expected_status="$3"
  local actual_status="$4"
  local elapsed_ns="$5"
  local expected_reason_code="${6:-}"
  local actual_reason_code="${7:-}"
  local passed=false
  if [[ "${expected_status}" == "${actual_status}" \
      && ( -z "${expected_reason_code}" || "${expected_reason_code}" == "${actual_reason_code}" ) ]]; then
    passed=true
  fi
  jq -cn \
    --arg caseId "${case_id}" \
    --arg stage "${stage}" \
    --argjson expectedStatus "${expected_status}" \
    --argjson actualStatus "${actual_status}" \
    --arg expectedReasonCode "${expected_reason_code}" \
    --arg actualReasonCode "${actual_reason_code}" \
    --argjson elapsedNs "${elapsed_ns}" \
    --argjson elapsedMs "$((elapsed_ns / 1000000))" \
    --argjson passed "${passed}" \
    '{caseId:$caseId,stage:$stage,expectedStatus:$expectedStatus,actualStatus:$actualStatus,expectedReasonCode:$expectedReasonCode,actualReasonCode:$actualReasonCode,elapsedNs:$elapsedNs,elapsedMs:$elapsedMs,passed:$passed}' \
    >> "${FAULT_CASES}"
  [[ "${passed}" == true ]]
}

http_status() {
  local token="$1"
  local response_file="${WORK_DIR}/response.json"
  local start_ns end_ns
  start_ns="$(date +%s%N)"
  HTTP_STATUS="$(curl --silent --show-error --output "${response_file}" --write-out '%{http_code}' \
    --connect-timeout 5 --max-time 30 --header "Authorization: Bearer ${token}" \
    "${GATEWAY_BASE_URL}${PROTECTED_PATH}" 2>/dev/null || true)"
  end_ns="$(date +%s%N)"
  HTTP_ELAPSED_NS=$((end_ns - start_ns))
  if ! [[ "${HTTP_STATUS}" =~ ^[0-9]{3}$ ]] || [[ "${HTTP_STATUS}" == "000" ]]; then
    HTTP_STATUS=0
  fi
}

recovery_request() {
  local response_file="$1"
  local headers_file="$2"
  local start_ns end_ns
  start_ns="$(date +%s%N)"
  RECOVERY_STATUS="$(curl --silent --show-error --output "${response_file}" --dump-header "${headers_file}" \
    --write-out '%{http_code}' --request POST --header 'Content-Type: application/json' \
    --connect-timeout 5 --max-time 15 --data-binary "@${F3_RECOVERY_BODY}" \
    "${GATEWAY_BASE_URL}${RECOVER_BY_KEY_PATH}" 2>/dev/null || printf '000')"
  end_ns="$(date +%s%N)"
  RECOVERY_ELAPSED_NS=$((end_ns - start_ns))
  if ! [[ "${RECOVERY_STATUS}" =~ ^[0-9]{3}$ ]] || [[ "${RECOVERY_STATUS}" == "000" ]]; then
    RECOVERY_STATUS=0
  fi
  RECOVERY_REASON_CODE="$(jq -r '.reasonCode // .decision // empty' "${response_file}" 2>/dev/null || true)"
}

prepare_recovery_fixture() {
  local suffix phone username password device_id register_body login_body login_response
  suffix="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:f3" | sha256sum | cut -c1-18)"
  phone="18$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:f3" | sha256sum | tr -cd '0-9' | cut -c1-9)"
  username="tdsc_f3_${suffix}"
  password="F3_${suffix}_pw"
  device_id="tdsc-f3-${suffix}"
  register_body="$(jq -cn --arg phone "${phone}" --arg username "${username}" --arg password "${password}" --arg displayName 'TDSC F3' '{phone:$phone,username:$username,password:$password,displayName:$displayName}')"
  login_body="$(jq -cn --arg username "${username}" --arg password "${password}" --arg deviceId "${device_id}" '{username:$username,password:$password,deviceId:$deviceId}')"
  curl --silent --show-error --request POST --header 'Content-Type: application/json' --data "${register_body}" \
    "${GATEWAY_BASE_URL}${REGISTER_PATH}" > /dev/null
  login_response="$(curl --silent --show-error --request POST --header 'Content-Type: application/json' --data "${login_body}" \
    "${GATEWAY_BASE_URL}${LOGIN_PATH}")"
  F3_ACCESS_TOKEN="$(printf '%s' "${login_response}" | jq -er '.data.accessToken')"
  F3_REFRESH_TOKEN="$(printf '%s' "${login_response}" | jq -er '.data.refreshToken')"
  F3_USER_ID="$(printf '%s' "${login_response}" | jq -er '.data.user.userId // .data.user.id')"
  F3_SOURCE_CARD_ID="$(printf '%s' "${login_response}" | jq -er '.data.currentCard.cardId')"
  [[ "${F3_USER_ID}" =~ ^[0-9]+$ && "${F3_SOURCE_CARD_ID}" =~ ^[0-9]+$ ]] \
    || fail 'F3 fixture login did not return numeric identifiers.'
  mysql_query "INSERT INTO user_card (user_id, card_type, card_status, priority, is_primary, created_at, updated_at) VALUES (${F3_USER_ID}, 'TDSC_F3_TARGET', 'ACTIVE', 200, 0, NOW(), NOW())"
  F3_TARGET_CARD_ID="$(mysql_query 'SELECT LAST_INSERT_ID()')"
  F3_IDEMPOTENCY_KEY="tdsc-f3-$(printf '%s' "${suffix}" | sha256sum | cut -c1-24)"
  F3_SWITCH_BODY="${WORK_DIR}/f3-switch.json"
  printf '%s' "$(jq -cn --argjson targetCardId "${F3_TARGET_CARD_ID}" --arg refreshToken "${F3_REFRESH_TOKEN}" --arg deviceId "${device_id}" '{targetCardId:$targetCardId,refreshToken:$refreshToken,deviceId:$deviceId}')" > "${F3_SWITCH_BODY}"
  F3_SWITCH_RESPONSE="${WORK_DIR}/f3-switch-response.json"
  F3_SWITCH_HEADERS="${WORK_DIR}/f3-switch-headers.txt"
  F3_SWITCH_STATUS="$(curl --silent --show-error --output "${F3_SWITCH_RESPONSE}" --dump-header "${F3_SWITCH_HEADERS}" \
    --write-out '%{http_code}' --request POST --header 'Content-Type: application/json' \
    --header "Authorization: Bearer ${F3_ACCESS_TOKEN}" --header "Idempotency-Key: ${F3_IDEMPOTENCY_KEY}" \
    --data-binary "@${F3_SWITCH_BODY}" "${GATEWAY_BASE_URL}${SWITCH_PATH}")"
  [[ "${F3_SWITCH_STATUS}" == "200" ]] || fail "F3 durable switch did not complete: status=${F3_SWITCH_STATUS}"
  F3_ORIGINAL_ACCESS_TOKEN="$(jq -er '.data.accessToken' "${F3_SWITCH_RESPONSE}")"
  F3_ORIGINAL_REFRESH_TOKEN="$(jq -er '.data.refreshToken' "${F3_SWITCH_RESPONSE}")"
  F3_RECOVERY_BODY="${WORK_DIR}/f3-recover.json"
  printf '%s' "$(jq -cn --arg idempotencyKey "${F3_IDEMPOTENCY_KEY}" --arg refreshToken "${F3_REFRESH_TOKEN}" '{idempotencyKey:$idempotencyKey,refreshToken:$refreshToken}')" > "${F3_RECOVERY_BODY}"
}

wait_for_gateway() {
  local attempt status
  for attempt in $(seq 1 60); do
    status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
      --request POST --header 'Content-Type: application/json' \
      --data '{"username":"not-ready","password":"not-ready"}' \
      "${GATEWAY_BASE_URL}${LOGIN_PATH}" 2>/dev/null || printf '000')"
    if [[ "${status}" != "000" && "${status}" != "502" && "${status}" != "503" && "${status}" != "504" ]]; then
      return 0
    fi
    sleep 2
  done
  fail 'Gateway did not become reachable during the fault-probe readiness window.'
}

bootstrap_runtime_user() {
  local suffix phone username password device_id register_body login_body login_response
  suffix="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:fault" | sha256sum | cut -c1-18)"
  phone="18$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:fault" | sha256sum | tr -cd '0-9' | cut -c1-9)"
  username="tdsc_fault_${suffix}"
  password="F_${suffix}_pw"
  device_id="tdsc-fault-${suffix}"
  register_body="$(jq -cn --arg phone "${phone}" --arg username "${username}" --arg password "${password}" --arg displayName 'TDSC Fault' '{phone:$phone,username:$username,password:$password,displayName:$displayName}')"
  login_body="$(jq -cn --arg username "${username}" --arg password "${password}" --arg deviceId "${device_id}" '{username:$username,password:$password,deviceId:$deviceId}')"
  curl --silent --show-error --request POST --header 'Content-Type: application/json' --data "${register_body}" \
    "${GATEWAY_BASE_URL}${REGISTER_PATH}" > /dev/null
  login_response="$(curl --silent --show-error --request POST --header 'Content-Type: application/json' --data "${login_body}" \
    "${GATEWAY_BASE_URL}${LOGIN_PATH}")"
  ACCESS_TOKEN="$(printf '%s' "${login_response}" | jq -er '.data.accessToken')"
  SOURCE_CARD="$(printf '%s' "${login_response}" | jq -er '.data.currentCard.cardId')"
  [[ "${SOURCE_CARD}" =~ ^[0-9]+$ ]] || fail 'Runtime fault fixture has no valid source card.'
  mysql_query "INSERT INTO permission_rule (card_id, resource_type, action_code, effect, priority, source_type, enabled, created_at, updated_at) VALUES (${SOURCE_CARD}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_FAULT_FIXTURE', 1, NOW(), NOW())"
}

wait_for_gateway
bootstrap_runtime_user
write_ack 'ready'

wait_for_stage 'redis-paused'
http_status "${ACCESS_TOKEN}"
record_fault_case F1_REDIS_PAUSED_AUTH_FAIL_CLOSED redis-paused 503 "${HTTP_STATUS}" "${HTTP_ELAPSED_NS}"
write_ack 'f1-paused-recorded'

wait_for_stage 'redis-resumed'
http_status "${ACCESS_TOKEN}"
record_fault_case F1_REDIS_RESUMED_AUTH_RECOVERED redis-resumed 200 "${HTTP_STATUS}" "${HTTP_ELAPSED_NS}"
write_ack 'f1-resumed-recorded'

wait_for_stage 'redis-restarted'
http_status "${ACCESS_TOKEN}"
record_fault_case F2_REDIS_RESTART_OLD_TOKEN_REJECTED redis-restarted 401 "${HTTP_STATUS}" "${HTTP_ELAPSED_NS}"
write_ack 'f2-restarted-recorded'

prepare_recovery_fixture
write_ack 'f3-fixture-ready'

wait_for_stage 'mysql-paused'
f3_paused_response="${WORK_DIR}/f3-recover-paused.json"
f3_paused_headers="${WORK_DIR}/f3-recover-paused.headers"
recovery_request "${f3_paused_response}" "${f3_paused_headers}"
record_fault_case F3_MYSQL_PAUSED_RECOVERY_TYPED_503 mysql-paused 503 "${RECOVERY_STATUS}" \
  "${RECOVERY_ELAPSED_NS}" DEPENDENCY_UNAVAILABLE "${RECOVERY_REASON_CODE}"
write_ack 'f3-paused-recorded'

wait_for_stage 'mysql-resumed'
f3_recovered_response="${WORK_DIR}/f3-recover-resumed.json"
f3_recovered_headers="${WORK_DIR}/f3-recover-resumed.headers"
for _ in $(seq 1 20); do
  recovery_request "${f3_recovered_response}" "${f3_recovered_headers}"
  if [[ "${RECOVERY_STATUS}" == "200" ]]; then
    break
  fi
  sleep 1
done
f3_original_access_fingerprint="$(printf '%s' "${F3_ORIGINAL_ACCESS_TOKEN}" | sha256sum | cut -d ' ' -f 1)"
f3_original_refresh_fingerprint="$(printf '%s' "${F3_ORIGINAL_REFRESH_TOKEN}" | sha256sum | cut -d ' ' -f 1)"
f3_recovered_access_fingerprint=""
f3_recovered_refresh_fingerprint=""
if [[ "${RECOVERY_STATUS}" == "200" ]]; then
  f3_recovered_access_token="$(jq -er '.data.accessToken' "${f3_recovered_response}")"
  f3_recovered_refresh_token="$(jq -er '.data.refreshToken' "${f3_recovered_response}")"
  f3_recovered_access_fingerprint="$(printf '%s' "${f3_recovered_access_token}" | sha256sum | cut -d ' ' -f 1)"
  f3_recovered_refresh_fingerprint="$(printf '%s' "${f3_recovered_refresh_token}" | sha256sum | cut -d ' ' -f 1)"
fi
f3_operation_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_operation WHERE user_id = ${F3_USER_ID} AND operation_type = 'SWITCH_CARD' AND idempotency_key_hash = SHA2('${F3_IDEMPOTENCY_KEY}', 256)")"
if [[ "${RECOVERY_STATUS}" != "200" || "${f3_original_access_fingerprint}" != "${f3_recovered_access_fingerprint}" \
    || "${f3_original_refresh_fingerprint}" != "${f3_recovered_refresh_fingerprint}" || "${f3_operation_count}" != "1" ]]; then
  record_fault_case F3_MYSQL_RESUMED_RECOVERY_SAME_RESPONSE mysql-resumed 200 "${RECOVERY_STATUS}" \
    "${RECOVERY_ELAPSED_NS}" SAME_RESPONSE DIVERGENT_RESPONSE
  fail 'F3 recovery after MySQL resumed did not return the original credential response.'
fi
record_fault_case F3_MYSQL_RESUMED_RECOVERY_SAME_RESPONSE mysql-resumed 200 200 \
  "${RECOVERY_ELAPSED_NS}" SAME_RESPONSE SAME_RESPONSE
write_ack 'f3-resumed-recorded'

jq -cn --arg runId "${TDSC_RUN_ID}" '{runId:$runId,implementedCases:[
  "F1_REDIS_PAUSED_AUTH_FAIL_CLOSED",
  "F1_REDIS_RESUMED_AUTH_RECOVERED",
  "F2_REDIS_RESTART_OLD_TOKEN_REJECTED",
  "F3_MYSQL_PAUSED_RECOVERY_TYPED_503",
  "F3_MYSQL_RESUMED_RECOVERY_SAME_RESPONSE"
]}' > "${FAULT_SUMMARY}"
jq -cn --arg runId "${TDSC_RUN_ID}" --argjson f3SingleDurableOperation true \
  '{runId:$runId,f3:{singleDurableOperation:$f3SingleDurableOperation},limitations:[
    "Container lifecycle operations are performed only by the host-side fault orchestrator; this in-network probe neither invokes nor requires container-control commands.",
    "The probe measures Redis pause/resume fail-closed access, old-token rejection after Redis restart, and MySQL availability classification during recover-by-key.",
    "Projection crash, outbox convergence, and parallel recovery are exercised by dedicated workloads rather than this fault probe."
  ]}' > "${FAULT_LIMITATIONS}"
write_ack 'complete'
