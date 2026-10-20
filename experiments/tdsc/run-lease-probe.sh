#!/usr/bin/env bash
set -euo pipefail

# Controlled two-worker lease evidence probe. It never writes authentication
# credentials, raw nonce values, Redis keys, payloads, or operation identifiers.

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
GATEWAY_BASE_URL="${GATEWAY_BASE_URL:?}"
TDSC_RUN_ID="${TDSC_RUN_ID:?}"
TDSC_SEED="${TDSC_SEED:?}"
TDSC_POST_CLAIM_GATE_NONCE="${TDSC_POST_CLAIM_GATE_NONCE:?}"
DB_HOST="${DB_HOST:?}"
DB_PORT="${DB_PORT:?}"
DB_NAME="${DB_NAME:?}"
DB_USERNAME="${DB_USERNAME:?}"
DB_PASSWORD="${DB_PASSWORD:?}"
REDIS_HOST="${REDIS_HOST:?}"
REDIS_PORT="${REDIS_PORT:?}"
STAGE_FILE="${TDSC_LEASE_STAGE_FILE:-${EVIDENCE_DIR}/lease-stage.txt}"
ACK_FILE="${TDSC_LEASE_ACK_FILE:-${EVIDENCE_DIR}/lease-ack.txt}"
WAIT_SECONDS="${TDSC_LEASE_STAGE_TIMEOUT_SECONDS:-120}"

readonly GATE_URL="http://identity-worker-a:9004/_internal/tdsc/session-projection-gate"
readonly SWITCH_PATH="/api/v1/auth/switch-card"
readonly PROTECTED_PATH="/main/api/v1/permission-rules/registry"
readonly LEASE_OWNER_A="identity-worker-a"
readonly LEASE_OWNER_B="identity-worker-b"

mkdir -p "${EVIDENCE_DIR}"
WORK_DIR="$(mktemp -d)"
EVIDENCE_FILE="${EVIDENCE_DIR}/lease-evidence.json"

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

write_ack() {
  local marker="$1"
  local temporary="${ACK_FILE}.tmp.$$"
  printf '%s\n' "${marker}" > "${temporary}"
  mv "${temporary}" "${ACK_FILE}"
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
        fail 'Host lease orchestrator aborted the probe.'
      fi
    fi
    sleep 1
  done
  fail "Timed out waiting for lease stage ${expected}."
}

sha256_text() {
  printf '%s' "$1" | sha256sum | cut -d ' ' -f 1
}

mysql_query() {
  MYSQL_PWD="${DB_PASSWORD}" mariadb --protocol=TCP --host="${DB_HOST}" --port="${DB_PORT}" \
    --user="${DB_USERNAME}" --database="${DB_NAME}" --batch --skip-column-names --raw --execute "$1"
}

mysql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

redis_has_key() {
  redis-cli --raw -h "${REDIS_HOST}" -p "${REDIS_PORT}" EXISTS "$1"
}

wait_for_gate_status() {
  local expected_state="$1"
  local attempt status_file http_status state
  status_file="${WORK_DIR}/gate-status.json"
  for attempt in $(seq 1 120); do
    http_status="$(curl --silent --show-error --output "${status_file}" --write-out '%{http_code}' \
      --header "X-TDSC-Gate-Nonce: ${TDSC_POST_CLAIM_GATE_NONCE}" "${GATE_URL}" 2>/dev/null || true)"
    state="$(jq -r '.state // empty' "${status_file}" 2>/dev/null || true)"
    if [[ "${http_status}" == "200" && "${state}" == "${expected_state}" ]]; then
      return 0
    fi
    sleep 1
  done
  fail "TDSC post-claim gate did not reach ${expected_state}; verify the multi-node profile and experimental gate settings."
}

http_json() {
  local method="$1"
  local path="$2"
  local body_file="$3"
  local authorization="${4:-}"
  local idempotency_key="${5:-}"
  local response_file="$6"
  local headers_file="$7"
  local curl_args=(--silent --show-error --output "${response_file}" --dump-header "${headers_file}" \
    --write-out '%{http_code}' --request "${method}" --header 'Content-Type: application/json' \
    --connect-timeout 5 --max-time 30)
  if [[ -n "${authorization}" ]]; then
    curl_args+=(--header "Authorization: Bearer ${authorization}")
  fi
  if [[ -n "${idempotency_key}" ]]; then
    curl_args+=(--header "Idempotency-Key: ${idempotency_key}")
  fi
  if [[ -n "${body_file}" ]]; then
    curl_args+=(--data-binary "@${body_file}")
  fi
  HTTP_STATUS="$(curl "${curl_args[@]}" "${GATEWAY_BASE_URL}${path}" || printf '000')"
}

wait_for_gateway() {
  local attempt response status
  response="${WORK_DIR}/gateway-ready.json"
  for attempt in $(seq 1 60); do
    status="$(curl --silent --show-error --output "${response}" --write-out '%{http_code}' \
      --request POST --header 'Content-Type: application/json' \
      --data '{"username":"not-ready","password":"not-ready"}' \
      "${GATEWAY_BASE_URL}/api/v1/auth/login" 2>/dev/null || true)"
    if [[ -n "${status}" && "${status}" != "000" && "${status}" != "502" && "${status}" != "503" ]]; then
      return 0
    fi
    sleep 2
  done
  fail 'Gateway did not become reachable within the lease probe readiness window.'
}

jwt_jti() {
  printf '%s' "$1" | cut -d '.' -f 2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -er '.jti'
}

wait_for_gateway
suffix="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:lease" | sha256sum | cut -c1-18)"
phone="18$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:lease" | sha256sum | tr -cd '0-9' | cut -c1-9)"
username="tdsc_lease_${suffix}"
password="L_${suffix}_pw"
device_id="tdsc-lease-${suffix}"
register_body="${WORK_DIR}/register.json"
login_body="${WORK_DIR}/login.json"
printf '%s' "$(jq -cn --arg phone "${phone}" --arg username "${username}" --arg password "${password}" --arg displayName "TDSC Lease ${suffix}" '{phone:$phone,username:$username,password:$password,displayName:$displayName}')" > "${register_body}"
printf '%s' "$(jq -cn --arg username "${username}" --arg password "${password}" --arg deviceId "${device_id}" '{username:$username,password:$password,deviceId:$deviceId}')" > "${login_body}"

register_response="${WORK_DIR}/register-response.json"
register_headers="${WORK_DIR}/register-headers.txt"
http_json POST /api/v1/auth/register "${register_body}" '' '' "${register_response}" "${register_headers}"
[[ "${HTTP_STATUS}" == "200" ]] || fail "Lease probe user registration failed: status=${HTTP_STATUS}"

login_response="${WORK_DIR}/login-response.json"
login_headers="${WORK_DIR}/login-headers.txt"
http_json POST /api/v1/auth/login "${login_body}" '' '' "${login_response}" "${login_headers}"
[[ "${HTTP_STATUS}" == "200" ]] || fail "Lease probe user login failed: status=${HTTP_STATUS}"

old_access_token="$(jq -er '.data.accessToken' "${login_response}")"
refresh_token="$(jq -er '.data.refreshToken' "${login_response}")"
user_id="$(jq -er '.data.user.userId // .data.user.id' "${login_response}")"
source_card_id="$(jq -er '.data.currentCard.cardId' "${login_response}")"
[[ "${user_id}" =~ ^[0-9]+$ && "${source_card_id}" =~ ^[0-9]+$ ]] || fail 'Lease probe login response lacks numeric identity values.'

mysql_query "INSERT INTO user_card (user_id, card_type, card_status, priority, is_primary, created_at, updated_at) VALUES (${user_id}, 'TDSC_LEASE_TARGET', 'ACTIVE', 200, 0, NOW(), NOW())"
target_card_id="$(mysql_query 'SELECT LAST_INSERT_ID()')"
mysql_query "INSERT INTO permission_rule (card_id, resource_type, action_code, effect, priority, source_type, enabled, created_at, updated_at) VALUES (${source_card_id}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_LEASE_FIXTURE', 1, NOW(), NOW()), (${target_card_id}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_LEASE_FIXTURE', 1, NOW(), NOW())"

old_jti="$(jwt_jti "${old_access_token}")"
old_jti_sha256="$(sha256_text "${old_jti}")"
idempotency_key="tdsc-lease-${old_jti_sha256:0:24}"
arm_status="${WORK_DIR}/gate-arm.json"
arm_http_status="000"
for _ in $(seq 1 60); do
  arm_http_status="$(curl --silent --show-error --output "${arm_status}" --write-out '%{http_code}' \
    --request POST --header "X-TDSC-Gate-Nonce: ${TDSC_POST_CLAIM_GATE_NONCE}" "${GATE_URL}/arm" 2>/dev/null || true)"
  if [[ "${arm_http_status}" == "200" ]]; then
    break
  fi
  sleep 1
done
[[ "${arm_http_status}" == "200" ]] || fail 'TDSC post-claim gate is unavailable or rejected arming; verify tdsc-fault profile, explicit gate enablement, and nonce configuration.'
switch_body="${WORK_DIR}/switch.json"
printf '%s' "$(jq -cn --argjson targetCardId "${target_card_id}" --arg refreshToken "${refresh_token}" --arg deviceId "${device_id}" '{targetCardId:$targetCardId,refreshToken:$refreshToken,deviceId:$deviceId}')" > "${switch_body}"

switch_response="${WORK_DIR}/switch-response.json"
switch_headers="${WORK_DIR}/switch-headers.txt"
http_json POST "${SWITCH_PATH}" "${switch_body}" "${old_access_token}" "${idempotency_key}" "${switch_response}" "${switch_headers}"
[[ "${HTTP_STATUS}" == "202" || "${HTTP_STATUS}" == "503" ]] || fail "Expected a pending switch while worker A is gated, got status=${HTTP_STATUS}."

wait_for_gate_status CLAIMED_WAITING
operation_id="$(mysql_query "SELECT operation_id FROM auth_session_operation WHERE user_id = ${user_id} AND operation_type = 'SWITCH_CARD' ORDER BY created_at DESC LIMIT 1")"
[[ -n "${operation_id}" ]] || fail 'Lease probe could not resolve the durable session operation.'
operation_sql="$(mysql_escape "${operation_id}")"
lease_before="$(mysql_query "SELECT sequence_number, CASE WHEN lease_owner = '${LEASE_OWNER_A}' THEN '${LEASE_OWNER_A}' WHEN lease_owner IS NULL THEN 'none' ELSE 'other' END FROM auth_session_outbox WHERE operation_id = '${operation_sql}' ORDER BY sequence_number, outbox_id LIMIT 1")"
lease_sequence="$(printf '%s' "${lease_before}" | cut -f1)"
lease_initial_owner="$(printf '%s' "${lease_before}" | cut -f2)"
[[ "${lease_sequence}" == "1" && "${lease_initial_owner}" == "${LEASE_OWNER_A}" ]] \
  || fail 'Worker A did not hold the first ordered outbox lease when the gate acknowledged claim.'
write_ack 'worker-a-claimed'

wait_for_stage 'worker-b-started'
sleep "${TDSC_LEASE_WAIT_SECONDS:-3}"
for _ in $(seq 1 60); do
  first_event_state="$(mysql_query "SELECT status, COALESCE(processed_by, 'none'), terminal_transitions FROM auth_session_outbox WHERE operation_id = '${operation_sql}' AND sequence_number = 1")"
  first_status="$(printf '%s' "${first_event_state}" | cut -f1)"
  first_processed_by="$(printf '%s' "${first_event_state}" | cut -f2)"
  first_transitions="$(printf '%s' "${first_event_state}" | cut -f3)"
  if [[ "${first_status}" == "PROCESSED" && "${first_processed_by}" == "${LEASE_OWNER_B}" && "${first_transitions}" == "1" ]]; then
    break
  fi
  sleep 1
done
[[ "${first_status}" == "PROCESSED" && "${first_processed_by}" == "${LEASE_OWNER_B}" && "${first_transitions}" == "1" ]] \
  || fail 'Worker B did not complete the expired first lease with one owner-fenced terminal transition.'
release_status="${WORK_DIR}/gate-release.json"
release_http_status="$(curl --silent --show-error --output "${release_status}" --write-out '%{http_code}' \
  --request POST --header "X-TDSC-Gate-Nonce: ${TDSC_POST_CLAIM_GATE_NONCE}" "${GATE_URL}/release" 2>/dev/null || true)"
[[ "${release_http_status}" == "200" ]] || fail 'TDSC post-claim gate release was rejected.'
wait_for_gate_status LEASE_LOST

for _ in $(seq 1 60); do
  operation_status="$(mysql_query "SELECT status FROM auth_session_operation WHERE operation_id = '${operation_sql}'")"
  if [[ "${operation_status}" == "COMPLETED" ]]; then
    break
  fi
  sleep 1
done
[[ "${operation_status}" == "COMPLETED" ]] || fail 'Lease probe operation did not converge to COMPLETED.'

recover_body="${WORK_DIR}/recover.json"
printf '%s' "$(jq -cn --arg idempotencyKey "${idempotency_key}" --arg refreshToken "${refresh_token}" '{idempotencyKey:$idempotencyKey,refreshToken:$refreshToken}')" > "${recover_body}"
recover_response="${WORK_DIR}/recover-response.json"
recover_headers="${WORK_DIR}/recover-headers.txt"
http_json POST /api/v1/auth/session-operations/recover-by-key "${recover_body}" '' '' "${recover_response}" "${recover_headers}"
[[ "${HTTP_STATUS}" == "200" ]] || fail "Lease probe recovery failed: status=${HTTP_STATUS}"
new_access_token="$(jq -er '.data.accessToken' "${recover_response}")"
new_jti="$(jwt_jti "${new_access_token}")"
new_jti_sha256="$(sha256_text "${new_jti}")"

old_response="${WORK_DIR}/old-token.json"
old_headers="${WORK_DIR}/old-token.headers"
http_json GET "${PROTECTED_PATH}" '' "${old_access_token}" '' "${old_response}" "${old_headers}"
old_token_status="${HTTP_STATUS}"
new_response="${WORK_DIR}/new-token.json"
new_headers="${WORK_DIR}/new-token.headers"
http_json GET "${PROTECTED_PATH}" '' "${new_access_token}" '' "${new_response}" "${new_headers}"
new_token_status="${HTTP_STATUS}"

outbox_summary="$(mysql_query "SELECT COUNT(*), SUM(status = 'PROCESSED'), SUM(terminal_transitions = 1), COUNT(DISTINCT processed_by), GROUP_CONCAT(DISTINCT CASE WHEN processed_by IN ('${LEASE_OWNER_A}', '${LEASE_OWNER_B}') THEN processed_by ELSE 'other' END ORDER BY processed_by SEPARATOR ',') FROM auth_session_outbox WHERE operation_id = '${operation_sql}'")"
outbox_count="$(printf '%s' "${outbox_summary}" | cut -f1)"
processed_count="$(printf '%s' "${outbox_summary}" | cut -f2)"
terminal_once_count="$(printf '%s' "${outbox_summary}" | cut -f3)"
processed_worker_count="$(printf '%s' "${outbox_summary}" | cut -f4)"
processed_workers="$(printf '%s' "${outbox_summary}" | cut -f5)"
durable_operation_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_operation WHERE user_id = ${user_id} AND operation_type = 'SWITCH_CARD' AND idempotency_key_hash = SHA2('${idempotency_key}', 256)")"

[[ "${old_token_status}" == "401" ]] || fail "Old token was not rejected after convergence: status=${old_token_status}"
[[ "${new_token_status}" == "200" ]] || fail "Replacement token was not accepted after convergence: status=${new_token_status}"
[[ "${outbox_count}" -ge 4 && "${outbox_count}" == "${processed_count}" && "${outbox_count}" == "${terminal_once_count}" ]] \
  || fail 'Every lease probe outbox row must reach one owner-fenced terminal transition.'
[[ "${processed_worker_count}" == "1" && "${processed_workers}" == "${LEASE_OWNER_B}" ]] \
  || fail 'Only worker B may complete the ordered projections after takeover.'
[[ "${durable_operation_count}" == "1" ]] || fail 'Recovery created an unexpected second durable session operation.'

jq -n \
  --arg runId "${TDSC_RUN_ID}" \
  --arg oldAccessJtiSha256 "${old_jti_sha256}" \
  --arg newAccessJtiSha256 "${new_jti_sha256}" \
  --arg initialLeaseOwner "${lease_initial_owner}" \
  --arg firstSequence "${lease_sequence}" \
  --arg firstProcessedBy "${first_processed_by}" \
  --arg processedWorkers "${processed_workers}" \
  --arg operationStatus "${operation_status}" \
  --argjson oldTokenStatus "${old_token_status}" \
  --argjson newTokenStatus "${new_token_status}" \
  --argjson outboxCount "${outbox_count}" \
  --argjson outboxProcessedCount "${processed_count}" \
  --argjson terminalOnceCount "${terminal_once_count}" \
  --argjson processedWorkerCount "${processed_worker_count}" \
  --argjson durableOperationCount "${durable_operation_count}" \
  '{runId:$runId,guarantee:"at-least-once Redis desired-state convergence with owner-fenced durable finalization",gate:{workerAClaimed:true,released:true,leaseLostAcknowledged:true},lease:{firstSequence:$firstSequence,initialOwner:$initialLeaseOwner,takeoverCompletedBy:$firstProcessedBy,processedWorkers:$processedWorkers},operationStatus:$operationStatus,oldAccessJtiSha256:$oldAccessJtiSha256,newAccessJtiSha256:$newAccessJtiSha256,oldTokenStatus:$oldTokenStatus,newTokenStatus:$newTokenStatus,durableOperationCount:$durableOperationCount,outbox:{eventCount:$outboxCount,processedCount:$outboxProcessedCount,terminalOnceCount:$terminalOnceCount,processedWorkerCount:$processedWorkerCount}}' \
  > "${EVIDENCE_FILE}"

write_ack 'complete'
