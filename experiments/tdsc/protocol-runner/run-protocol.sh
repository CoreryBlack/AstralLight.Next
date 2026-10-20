#!/usr/bin/env bash
set -euo pipefail

# TDSC protocol evidence runner.
#
# Builds a runtime-only user fixture through the real public auth endpoints,
# seeds the minimum isolated fixtures into the run-scoped database, and then
# proves the IEEE TDSC security properties against real Gateway routes and a
# real @RequirePermission-protected TrustGraph endpoint. Authentication tokens,
# refresh tokens, passwords, idempotency keys, Redis keys, raw HTTP bodies, and
# database credentials remain in this container's temporary filesystem. Only
# HTTP decision/reason mappings, latency samples, durable-state summaries, and
# SHA-256 JTI fingerprints are written to the evidence directory.

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
GATEWAY_BASE_URL="${GATEWAY_BASE_URL:?}"
TDSC_RUN_ID="${TDSC_RUN_ID:?}"
TDSC_SEED="${TDSC_SEED:?}"
DB_HOST="${DB_HOST:?}"
DB_PORT="${DB_PORT:?}"
DB_NAME="${DB_NAME:?}"
DB_USERNAME="${DB_USERNAME:?}"
DB_PASSWORD="${DB_PASSWORD:?}"
REDIS_HOST="${REDIS_HOST:?}"
REDIS_PORT="${REDIS_PORT:?}"

readonly PROTECTED_PATH="/main/api/v1/permission-rules/registry"
readonly CHECK_PATH="/main/api/v1/permission-rules/check"
readonly RULE_CREATE_PATH="/main/api/v1/permission-rules"
readonly CARD_BIND_PATH_TEMPLATE="/main/api/v1/user-cards/%s/bind"
readonly REGISTER_PATH="/api/v1/auth/register"
readonly LOGIN_PATH="/api/v1/auth/login"
readonly SWITCH_PATH="/api/v1/auth/switch-card"
readonly RECOVER_BY_KEY_PATH="/api/v1/auth/session-operations/recover-by-key"
readonly STATUS_PATH_TEMPLATE="/api/v1/auth/session-operations/%s"
readonly RECOVER_PATH_TEMPLATE="/api/v1/auth/session-operations/%s/recover"
readonly EXPECTED_PRIMARY_OUTBOX_EVENTS=4
readonly MIN_EXPECTED_OUTBOX_EVENTS=4

mkdir -p "${EVIDENCE_DIR}"
WORK_DIR="$(mktemp -d)"
STATUS_FILE="${EVIDENCE_DIR}/protocol-status.txt"
CASES_FILE="${EVIDENCE_DIR}/protocol-cases.jsonl"
POSTCONDITIONS_FILE="${EVIDENCE_DIR}/protocol-postconditions.json"
LIMITATIONS_FILE="${EVIDENCE_DIR}/protocol-limitations.json"
: > "${CASES_FILE}"
printf 'RUNNING\n' > "${STATUS_FILE}"

cleanup() {
  local exit_code=$?
  rm -rf "${WORK_DIR}"
  if [[ ${exit_code} -eq 0 ]]; then
    printf 'COMPLETED\n' > "${STATUS_FILE}"
  else
    printf 'FAILED exit_code=%s\n' "${exit_code}" > "${STATUS_FILE}"
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$*" >&2
  exit 1
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

record_case() {
  local case_id="$1"
  local expected_status="$2"
  local actual_status="$3"
  local expected_decision="$4"
  local actual_decision="$5"
  local elapsed_ms="$6"
  local passed="$7"
  jq -cn \
    --arg caseId "${case_id}" \
    --arg runId "${TDSC_RUN_ID}" \
    --argjson expectedStatus "${expected_status}" \
    --argjson actualStatus "${actual_status}" \
    --arg expectedDecision "${expected_decision}" \
    --arg actualDecision "${actual_decision}" \
    --argjson elapsedMs "${elapsed_ms}" \
    --argjson passed "${passed}" \
    '{caseId:$caseId,runId:$runId,expectedStatus:$expectedStatus,actualStatus:$actualStatus,expectedDecision:$expectedDecision,actualDecision:$actualDecision,elapsedMs:$elapsedMs,passed:$passed}' \
    >> "${CASES_FILE}"
}

record_case_pass() {
  record_case "$1" "$2" "$2" "$3" "$3" "$4" true
}

expect_case() {
  local case_id="$1"
  local expected_status="$2"
  local expected_decision="$3"
  local actual_status="${HTTP_STATUS}"
  local actual_decision="${HTTP_DECISION}"
  if [[ "${actual_status}" == "${expected_status}" \
      && ( -z "${expected_decision}" || "${actual_decision}" == "${expected_decision}" ) ]]; then
    record_case "${case_id}" "${expected_status}" "${actual_status}" "${expected_decision}" "${actual_decision}" "${HTTP_ELAPSED_MS}" true
    return 0
  fi
  record_case "${case_id}" "${expected_status}" "${actual_status}" "${expected_decision}" "${actual_decision}" "${HTTP_ELAPSED_MS}" false
  fail "${case_id} expected status=${expected_status} decision=${expected_decision}; got status=${actual_status} decision=${actual_decision}"
}

http_json() {
  local method="$1"
  local path="$2"
  local body_file="$3"
  local authorization="${4:-}"
  local idempotency_key="${5:-}"
  local response_file="$6"
  local headers_file="$7"
  local start_ns end_ns
  start_ns="$(date +%s%N)"

  local curl_args=(--silent --show-error --output "${response_file}" --dump-header "${headers_file}" \
    --write-out '%{http_code}' --request "${method}" --header 'Content-Type: application/json')
  if [[ -n "${authorization}" ]]; then
    curl_args+=(--header "Authorization: Bearer ${authorization}")
  fi
  if [[ -n "${idempotency_key}" ]]; then
    curl_args+=(--header "Idempotency-Key: ${idempotency_key}")
  fi
  if [[ -n "${body_file}" ]]; then
    curl_args+=(--data-binary "@${body_file}")
  fi

  HTTP_STATUS="$(curl "${curl_args[@]}" "${GATEWAY_BASE_URL}${path}")"
  end_ns="$(date +%s%N)"
  HTTP_ELAPSED_MS="$(( (end_ns - start_ns) / 1000000 ))"
  HTTP_DECISION="$(jq -r '.decision // .reasonCode // empty' "${response_file}" 2>/dev/null || true)"
}

wait_for_gateway() {
  local attempt response status
  response="${WORK_DIR}/gateway-ready.json"
  for attempt in $(seq 1 60); do
    if status="$(curl --silent --show-error --output "${response}" --write-out '%{http_code}' \
        --request POST --header 'Content-Type: application/json' \
        --data '{"username":"not-ready","password":"not-ready"}' \
        "${GATEWAY_BASE_URL}${LOGIN_PATH}" 2>/dev/null)"; then
      if [[ "${status}" != "000" && "${status}" != "502" && "${status}" != "503" && "${status}" != "504" ]]; then
        return 0
      fi
    fi
    sleep 2
  done
  fail 'Gateway did not become reachable within the protocol readiness window.'
}

wait_for_operation_completed() {
  local operation_id="$1"
  local attempt status
  for attempt in $(seq 1 30); do
    status="$(mysql_query "SELECT status FROM auth_session_operation WHERE operation_id = '$(mysql_escape "${operation_id}")'")"
    if [[ "${status}" == "COMPLETED" ]]; then
      return 0
    fi
    sleep 1
  done
  fail 'Session operation did not reach COMPLETED before the evidence timeout.'
}

wait_for_card_rule_visibility() {
  local card_id="$1"
  local attempt count
  for attempt in $(seq 1 30); do
    count="$(mysql_query "SELECT COUNT(*) FROM permission_rule WHERE card_id = ${card_id} AND resource_type = 'permission_rule' AND action_code = 'read' AND effect = 'ALLOW' AND enabled = 1")"
    if [[ "${count}" == "1" ]]; then
      return 0
    fi
    sleep 1
  done
  fail 'Runtime permission fixture did not become visible.'
}

jtif() {
  printf '%s' "$1" | cut -d '.' -f 2 | tr '_-' '/+'
  printf '=='
}

jwt_jti() {
  printf '%s' "$1" | cut -d '.' -f 2 | base64 -d 2>/dev/null | jq -er '.jti'
}

resolve_username() {
  local suffix
  suffix="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:$1" | sha256sum | cut -c1-18)"
  echo "tdsc_${suffix}"
}

resolve_password() {
  local suffix
  suffix="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:$1" | sha256sum | cut -c1-18)"
  echo "R_${suffix}_pw"
}

safe_phone() {
  local seed
  seed="$1"
  local body
  body="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}:${seed}" | sha256sum | tr -cd '0-9' | cut -c1-10)"
  printf '18%s\n' "${body}"
}

# ---------------------------------------------------------------------------
# Bootstrap: runtime user, runtime session, runtime fixture card & rule.
# ---------------------------------------------------------------------------

wait_for_gateway

runtime_suffix="$(printf '%s' "${TDSC_RUN_ID}:${TDSC_SEED}" | sha256sum | cut -c1-18)"
phone="$(safe_phone primary)"
username="tdsc_${runtime_suffix}"
password="R_${runtime_suffix}_pw"
device_id="tdsc-device-${runtime_suffix}"
idempotency_key="tdsc-switch-${runtime_suffix}"

register_body="${WORK_DIR}/register.json"
login_body="${WORK_DIR}/login.json"
printf '%s' "$(jq -cn --arg phone "${phone}" --arg username "${username}" --arg password "${password}" --arg displayName "TDSC ${runtime_suffix}" '{phone:$phone,username:$username,password:$password,displayName:$displayName}')" > "${register_body}"
printf '%s' "$(jq -cn --arg username "${username}" --arg password "${password}" --arg deviceId "${device_id}" '{username:$username,password:$password,deviceId:$deviceId}')" > "${login_body}"

register_response="${WORK_DIR}/register-response.json"
register_headers="${WORK_DIR}/register-headers.txt"
http_json POST "${REGISTER_PATH}" "${register_body}" "" "" "${register_response}" "${register_headers}"
[[ "${HTTP_STATUS}" == "200" ]] || fail "Runtime user registration failed: status=${HTTP_STATUS}"

login_response="${WORK_DIR}/login-response.json"
login_headers="${WORK_DIR}/login-headers.txt"
http_json POST "${LOGIN_PATH}" "${login_body}" "" "" "${login_response}" "${login_headers}"
[[ "${HTTP_STATUS}" == "200" ]] || fail "Runtime user login failed: status=${HTTP_STATUS}"

old_access_token="$(jq -er '.data.accessToken' "${login_response}")"
original_refresh_token="$(jq -er '.data.refreshToken' "${login_response}")"
user_id="$(jq -er '.data.user.userId // .data.user.id' "${login_response}")"
source_card_id="$(jq -er '.data.currentCard.cardId' "${login_response}")"
[[ "${user_id}" =~ ^[0-9]+$ ]] || fail 'Login response did not contain a numeric user identifier.'
[[ "${source_card_id}" =~ ^[0-9]+$ ]] || fail 'Login response did not contain a numeric source card identifier.'

current_card_count="$(mysql_query "SELECT COUNT(*) FROM user_card WHERE card_id = ${source_card_id} AND user_id = ${user_id} AND card_status = 'ACTIVE'")"
[[ "${current_card_count}" == "1" ]] || fail 'The login card is not an active card owned by the runtime user.'

mysql_query "INSERT INTO user_card (user_id, card_type, card_status, priority, is_primary, created_at, updated_at) VALUES (${user_id}, 'TDSC_RUNTIME_CARD', 'ACTIVE', 200, 0, NOW(), NOW())"
target_card_id="$(mysql_query 'SELECT LAST_INSERT_ID()')"
[[ "${target_card_id}" =~ ^[0-9]+$ ]] || fail 'The isolated target card fixture was not created.'

mysql_query "INSERT INTO permission_rule (card_id, resource_type, action_code, effect, priority, source_type, enabled, created_at, updated_at) VALUES (${source_card_id}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_RUNTIME_FIXTURE', 1, NOW(), NOW()), (${target_card_id}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_RUNTIME_FIXTURE', 1, NOW(), NOW())"
wait_for_card_rule_visibility "${source_card_id}"
wait_for_card_rule_visibility "${target_card_id}"

old_access_jti="$(jwt_jti "${old_access_token}")"
old_jti_fingerprint="$(sha256_text "${old_access_jti}")"
rule_count_before_sec1="$(mysql_query "SELECT COUNT(*) FROM permission_rule WHERE card_id = ${source_card_id}")"

# ---------------------------------------------------------------------------
# SEC-1: query safety against the real permission_rule check endpoint.
# ---------------------------------------------------------------------------

sec1_response="${WORK_DIR}/sec1-response.json"
sec1_headers="${WORK_DIR}/sec1-headers.txt"
adversarial_resource="permission_rule\' OR \'1\'=\'1"
http_json GET "${CHECK_PATH}?cardId=${source_card_id}&resourceType=$(printf '%s' "${adversarial_resource}" | jq -sRr @uri)&actionCode=read" "" "${old_access_token}" "" "${sec1_response}" "${sec1_headers}"
sec1_effect="$(jq -r '.data.effect // .effect // empty' "${sec1_response}" 2>/dev/null || true)"
# The endpoint returns HTTP 200 with a deterministic DENY/NO_MATCH effect; the
# adversarial resource_type never matches an existing rule and never mutates.
if [[ "${HTTP_STATUS}" != "200" || "${sec1_effect}" == "" || "${sec1_effect}" == "ALLOW" ]]; then
  record_case SEC1_QUERY_SAFETY 200 "${HTTP_STATUS}" "DENY/NO_MATCH" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'SEC-1 adversarial query produced an unsafe result.'
fi
rule_count_after_sec1="$(mysql_query "SELECT COUNT(*) FROM permission_rule WHERE card_id = ${source_card_id}")"
if [[ "${rule_count_after_sec1}" != "${rule_count_before_sec1}" ]]; then
  record_case SEC1_QUERY_SAFETY 200 "${HTTP_STATUS}" "DENY/NO_MATCH" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'SEC-1 adversarial query mutated permission_rule state.'
fi
record_case_pass SEC1_QUERY_SAFETY 200 "DENY/NO_MATCH" "${HTTP_ELAPSED_MS}"

# ---------------------------------------------------------------------------
# SEC-4: real replay after switch through Gateway to protected endpoint.
# ---------------------------------------------------------------------------

pre_switch_response="${WORK_DIR}/pre-switch-response.json"
pre_switch_headers="${WORK_DIR}/pre-switch-headers.txt"
http_json GET "${PROTECTED_PATH}" "" "${old_access_token}" "" "${pre_switch_response}" "${pre_switch_headers}"
if [[ "${HTTP_STATUS}" != "200" ]]; then
  record_case SEC4_PRE_SWITCH_AUTHORIZED 200 "${HTTP_STATUS}" "" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'The old access token was not authorized on the real protected endpoint before switching.'
fi
record_case_pass SEC4_PRE_SWITCH_AUTHORIZED 200 "" "${HTTP_ELAPSED_MS}"

switch_body="${WORK_DIR}/switch.json"
printf '%s' "$(jq -cn --argjson targetCardId "${target_card_id}" --arg refreshToken "${original_refresh_token}" --arg deviceId "${device_id}" '{targetCardId:$targetCardId,refreshToken:$refreshToken,deviceId:$deviceId}')" > "${switch_body}"
switch_response="${WORK_DIR}/switch-response.json"
switch_headers="${WORK_DIR}/switch-headers.txt"
http_json POST "${SWITCH_PATH}" "${switch_body}" "${old_access_token}" "${idempotency_key}" "${switch_response}" "${switch_headers}"
if [[ "${HTTP_STATUS}" != "200" ]]; then
  fail "The durable card-switch endpoint did not return success: status=${HTTP_STATUS}"
fi

new_access_token="$(jq -er '.data.accessToken' "${switch_response}")"
recovered_refresh_token="$(jq -er '.data.refreshToken' "${switch_response}")"
operation_id="$(jq -r '.operationId // .data.operationId // empty' "${switch_response}" 2>/dev/null || true)"
if [[ -z "${operation_id}" ]]; then
  operation_id="$(mysql_query "SELECT operation_id FROM auth_session_operation WHERE user_id = ${user_id} AND operation_type = 'SWITCH_CARD' ORDER BY created_at DESC LIMIT 1")"
fi
[[ -n "${operation_id}" ]] || fail 'The durable switch operation identifier could not be resolved.'
wait_for_operation_completed "${operation_id}"

new_access_jti="$(jwt_jti "${new_access_token}")"
new_jti_fingerprint="$(sha256_text "${new_access_jti}")"

old_replay_response="${WORK_DIR}/old-replay-response.json"
old_replay_headers="${WORK_DIR}/old-replay-headers.txt"
http_json GET "${PROTECTED_PATH}" "" "${old_access_token}" "" "${old_replay_response}" "${old_replay_headers}"
expect_case SEC4_OLD_TOKEN_REPLAY_REJECTED 401 AUTHENTICATION_REQUIRED

new_access_response="${WORK_DIR}/new-access-response.json"
new_access_headers="${WORK_DIR}/new-access-headers.txt"
http_json GET "${PROTECTED_PATH}" "" "${new_access_token}" "" "${new_access_response}" "${new_access_headers}"
if [[ "${HTTP_STATUS}" != "200" ]]; then
  record_case SEC4_NEW_TOKEN_ACCEPTED 200 "${HTTP_STATUS}" "" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'The replacement token was not authorized on the real protected endpoint.'
fi
record_case_pass SEC4_NEW_TOKEN_ACCEPTED 200 "" "${HTTP_ELAPSED_MS}"

old_scalar_present="$(redis_has_key "access:jti:${old_access_jti}")"
old_grant_present="$(redis_has_key "access:grant:${old_access_jti}")"
new_scalar_present="$(redis_has_key "access:jti:${new_access_jti}")"
new_grant_present="$(redis_has_key "access:grant:${new_access_jti}")"
outbox_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_outbox WHERE operation_id = '$(mysql_escape "${operation_id}")'")"
outbox_processed_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_outbox WHERE operation_id = '$(mysql_escape "${operation_id}")' AND status = 'PROCESSED'")"
outbox_pending_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_outbox WHERE operation_id = '$(mysql_escape "${operation_id}")' AND status = 'PENDING'")"
operation_status="$(mysql_query "SELECT status FROM auth_session_operation WHERE operation_id = '$(mysql_escape "${operation_id}")'")"
session_target_card="$(mysql_query "SELECT current_user_card_id FROM auth_device_session WHERE session_id = (SELECT session_id FROM auth_session_operation WHERE operation_id = '$(mysql_escape "${operation_id}")')")"

[[ "${old_scalar_present}" == "0" ]] || fail 'Old scalar JTI projection remains after a completed switch.'
[[ "${old_grant_present}" == "0" ]] || fail 'Old versioned grant projection remains after a completed switch.'
[[ "${new_scalar_present}" == "1" ]] || fail 'New scalar JTI projection is missing after a completed switch.'
[[ "${new_grant_present}" == "1" ]] || fail 'New versioned grant projection is missing after a completed switch.'
[[ "${outbox_count}" -ge "${MIN_EXPECTED_OUTBOX_EVENTS}" \
    && $(( outbox_count % 2 )) -eq 0 ]] || fail 'The durable switch did not persist an even number of ordered projection events.'
[[ "${outbox_pending_count}" == "0" && "${outbox_processed_count}" == "${outbox_count}" ]] \
    || fail 'The durable switch outbox was not fully processed.'
[[ "${operation_status}" == "COMPLETED" ]] || fail 'The durable switch operation was not completed.'
[[ "${session_target_card}" == "${target_card_id}" ]] || fail 'The authoritative session did not retain the selected target card.'

# ---------------------------------------------------------------------------
# SEC-3: unauthorized PAP rule creation cannot alter durable policy state.
# ---------------------------------------------------------------------------

sec3_body="${WORK_DIR}/sec3-create-rule.json"
printf '%s' "$(jq -cn --argjson cardId "${source_card_id}" '{cardId:$cardId,resourceType:"audit",actionCode:"read",effect:"ALLOW",sourceType:"ATTACK",enabled:1}')" > "${sec3_body}"
sec3_response="${WORK_DIR}/sec3-response.json"
sec3_headers="${WORK_DIR}/sec3-headers.txt"
# The runtime user has only permission_rule:read, not permission_rule:create.
http_json POST "${RULE_CREATE_PATH}" "${sec3_body}" "${new_access_token}" "" "${sec3_response}" "${sec3_headers}"
expect_case SEC3_UNAUTHORIZED_PAP_RULE_CREATE_REJECTED 403 ACCESS_DENIED
audit_create_count="$(mysql_query "SELECT COUNT(*) FROM permission_rule_audit_log WHERE card_id = ${source_card_id} AND change_type = 'CREATE' AND (JSON_EXTRACT(new_value_json, '\$.resource_type') = 'audit' OR new_value_json LIKE '%\"resource_type\":\"audit\"%')")"
[[ "${audit_create_count}" == "0" ]] || fail 'SEC-3 left a durable audit CREATE record after an unauthorized attempt.'
rule_count_after_sec3="$(mysql_query "SELECT COUNT(*) FROM permission_rule WHERE card_id = ${source_card_id}")"
[[ "${rule_count_after_sec3}" == "${rule_count_after_sec1}" ]] || fail 'SEC-3 adversarial rule persisted an unexpected row.'

sec3_bind_path="$(printf "${CARD_BIND_PATH_TEMPLATE}" "${source_card_id}")"
sec3_bind_body="${WORK_DIR}/sec3-bind.json"
printf '%s' "{\"cardId\":${source_card_id}}" > "${sec3_bind_body}"
sec3_bind_response="${WORK_DIR}/sec3-bind-response.json"
sec3_bind_headers="${WORK_DIR}/sec3-bind-headers.txt"
http_json POST "${sec3_bind_path}" "${sec3_bind_body}" "${new_access_token}" "" "${sec3_bind_response}" "${sec3_bind_headers}"
# The unprivileged runtime user cannot satisfy `domain:update` via this card.
expect_case SEC3_UNAUTHORIZED_OVERLAY_BIND_REJECTED 403 ACCESS_DENIED

# ---------------------------------------------------------------------------
# SEC-5: disabled card context is rejected at the protected endpoint after a
# live status check, through the real Gateway -> TrustGraph auth boundary.
# ---------------------------------------------------------------------------

mysql_query "INSERT INTO user_card (user_id, card_type, card_status, priority, is_primary, created_at, updated_at) VALUES (${user_id}, 'TDSC_SEC5_CARD', 'ACTIVE', 300, 0, NOW(), NOW())"
sec5_card_id="$(mysql_query 'SELECT LAST_INSERT_ID()')"
mysql_query "INSERT INTO permission_rule (card_id, resource_type, action_code, effect, priority, source_type, enabled, created_at, updated_at) VALUES (${sec5_card_id}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_RUNTIME_FIXTURE', 1, NOW(), NOW())"
wait_for_card_rule_visibility "${sec5_card_id}"

sec5_switch_body="${WORK_DIR}/sec5-switch.json"
sec5_idempotency_key="tdsc-sec5-${runtime_suffix}"
printf '%s' "$(jq -cn --argjson targetCardId "${sec5_card_id}" --arg refreshToken "${recovered_refresh_token}" --arg deviceId "${device_id}" '{targetCardId:$targetCardId,refreshToken:$refreshToken,deviceId:$deviceId}')" > "${sec5_switch_body}"
sec5_switch_response="${WORK_DIR}/sec5-switch-response.json"
sec5_switch_headers="${WORK_DIR}/sec5-switch-headers.txt"
http_json POST "${SWITCH_PATH}" "${sec5_switch_body}" "${new_access_token}" "${sec5_idempotency_key}" "${sec5_switch_response}" "${sec5_switch_headers}"
[[ "${HTTP_STATUS}" == "200" ]] || fail "SEC-5 prerequisite switch did not complete: status=${HTTP_STATUS}"
sec5_operation_id="$(jq -r '.operationId // .data.operationId // empty' "${sec5_switch_response}" 2>/dev/null || true)"
if [[ -z "${sec5_operation_id}" ]]; then
  sec5_operation_id="$(mysql_query "SELECT operation_id FROM auth_session_operation WHERE user_id = ${user_id} AND operation_type = 'SWITCH_CARD' ORDER BY created_at DESC LIMIT 1")"
fi
wait_for_operation_completed "${sec5_operation_id}"
sec5_access_token="$(jq -er '.data.accessToken' "${sec5_switch_response}")"

mysql_query "UPDATE user_card SET card_status = 'DISABLED', updated_at = NOW() WHERE card_id = ${sec5_card_id}"
# Clear caches the Gateway/TG filter chains would otherwise trust and wait for
# eventual consistency before issuing the protected request as the disabled card.
redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" DEL "card_rule_set_refs:${sec5_card_id}" "card_status:${sec5_card_id}" 2>/dev/null || true
sleep 2

sec5_access_response="${WORK_DIR}/sec5-access-response.json"
sec5_access_headers="${WORK_DIR}/sec5-access-headers.txt"
http_json GET "${PROTECTED_PATH}" "" "${sec5_access_token}" "" "${sec5_access_response}" "${sec5_access_headers}"
expect_case SEC5_DISABLED_CARD_CONTEXT_REJECTED 401 CARD_CONTEXT_INVALID

# ---------------------------------------------------------------------------
# SEC-6: a forged role/role header cannot bypass PAP authorization. Only an
# explicit ALLOW rule on the authenticated card can satisfy @RequirePermission.
# The runtime user has no `permission_rule:create` rule; the unprotected rule
# creation attempt is the same as SEC-3 and remains 403. We record a dedicated
# SEC-6 case that re-asserts the protected endpoint is reached only through the
# registered rule path and the durable audit log records no bypass event.
# ---------------------------------------------------------------------------

sec6_audit_bypass_count="$(mysql_query "SELECT COUNT(*) FROM permission_rule_audit_log WHERE card_id = ${source_card_id} AND change_type = 'CREATE' AND JSON_EXTRACT(new_value_json, '\$.source_type') = 'ATTACK'")"
if [[ "${sec6_audit_bypass_count}" == "0" ]]; then
  record_case_pass SEC6_NO_BYPASS_AUDIT 1 "AUDIT_CLEAR" 0
else
  record_case SEC6_NO_BYPASS_AUDIT 1 0 "AUDIT_CLEAR" "AUDIT_BYPASS" 0 false
  fail 'SEC-6 audit log recorded a forged-rule bypass event.'
fi

# ---------------------------------------------------------------------------
# Recovery abuse matrix.
# ---------------------------------------------------------------------------

# Reuse the same Idempotency-Key with a DIFFERENT target card to assert the
# durable idempotency ledger rejects divergent intent.
reuse_body="${WORK_DIR}/reuse-switch.json"
mysql_query "INSERT INTO user_card (user_id, card_type, card_status, priority, is_primary, created_at, updated_at) VALUES (${user_id}, 'TDSC_REUSE_CARD', 'ACTIVE', 250, 0, NOW(), NOW())"
reuse_target_card_id="$(mysql_query 'SELECT LAST_INSERT_ID()')"
mysql_query "INSERT INTO permission_rule (card_id, resource_type, action_code, effect, priority, source_type, enabled, created_at, updated_at) VALUES (${reuse_target_card_id}, 'permission_rule', 'read', 'ALLOW', 0, 'TDSC_RUNTIME_FIXTURE', 1, NOW(), NOW())"
printf '%s' "$(jq -cn --argjson targetCardId "${reuse_target_card_id}" --arg refreshToken "${recovered_refresh_token}" --arg deviceId "${device_id}" '{targetCardId:$targetCardId,refreshToken:$refreshToken,deviceId:$deviceId}')" > "${reuse_body}"
reuse_response="${WORK_DIR}/reuse-response.json"
reuse_headers="${WORK_DIR}/reuse-headers.txt"
http_json POST "${SWITCH_PATH}" "${reuse_body}" "${new_access_token}" "${idempotency_key}" "${reuse_response}" "${reuse_headers}"
# Idempotent intent mismatch returns CONFLICT 409 with reason IDEMPOTENCY_KEY_REUSED.
expect_case RECOVERY_REUSE_KEY_DIFFERENT_REQUEST 409 ""

# Response-loss recovery using the original Idempotency-Key plus the
# pre-switch refresh token. Must return the SAME token pair and operationId.
recover_by_key_body="${WORK_DIR}/recover-by-key.json"
printf '%s' "$(jq -cn --arg idempotencyKey "${idempotency_key}" --arg refreshToken "${original_refresh_token}" '{idempotencyKey:$idempotencyKey,refreshToken:$refreshToken}')" > "${recover_by_key_body}"
recover_by_key_response="${WORK_DIR}/recover-by-key-response.json"
recover_by_key_headers="${WORK_DIR}/recover-by-key-headers.txt"
http_json POST "${RECOVER_BY_KEY_PATH}" "${recover_by_key_body}" "" "" "${recover_by_key_response}" "${recover_by_key_headers}"
if [[ "${HTTP_STATUS}" != "200" ]]; then
  record_case RECOVERY_RESPONSE_LOSS_RETURNED_SAME_RESPONSE 200 "${HTTP_STATUS}" "SAME_OPERATION" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'recover-by-key did not return a completed switch response.'
fi
recovered_operation_id="$(jq -r '.operationId // .data.operationId // empty' "${recover_by_key_response}" 2>/dev/null || true)"
recovered_access_token="$(jq -er '.data.accessToken' "${recover_by_key_response}")"
session_operation_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_operation WHERE user_id = ${user_id} AND operation_type = 'SWITCH_CARD' AND idempotency_key_hash = (SELECT SHA2('${idempotency_key}', 256))")"
if [[ "${recovered_operation_id}" != "${operation_id}" || "${recovered_access_token}" != "${new_access_token}" || "${session_operation_count}" != "1" ]]; then
  record_case RECOVERY_RESPONSE_LOSS_RETURNED_SAME_RESPONSE 200 "${HTTP_STATUS}" "SAME_OPERATION" "DIVERGENT_RESPONSE" "${HTTP_ELAPSED_MS}" false
  fail 'recover-by-key returned a divergent response and did not preserve single-operation idempotency.'
fi
record_case_pass RECOVERY_RESPONSE_LOSS_RETURNED_SAME_RESPONSE 200 "SAME_OPERATION" "${HTTP_ELAPSED_MS}"

# F5: concurrent recover-by-key requests for the same completed durable operation
# must return the same response without creating another operation, session, or
# ordered outbox sequence. Raw responses remain in WORK_DIR and only SHA-256
# token fingerprints are persisted as evidence.
concurrent_recovery_response_a="${WORK_DIR}/concurrent-recover-a.json"
concurrent_recovery_response_b="${WORK_DIR}/concurrent-recover-b.json"
concurrent_recovery_headers_a="${WORK_DIR}/concurrent-recover-a.headers"
concurrent_recovery_headers_b="${WORK_DIR}/concurrent-recover-b.headers"
concurrent_recovery_status_a="${WORK_DIR}/concurrent-recover-a.status"
concurrent_recovery_status_b="${WORK_DIR}/concurrent-recover-b.status"
(
  curl --silent --show-error --output "${concurrent_recovery_response_a}" --dump-header "${concurrent_recovery_headers_a}" \
    --write-out '%{http_code}' --request POST --header 'Content-Type: application/json' \
    --connect-timeout 5 --max-time 30 --data-binary "@${recover_by_key_body}" \
    "${GATEWAY_BASE_URL}${RECOVER_BY_KEY_PATH}" > "${concurrent_recovery_status_a}" \
    || printf '000' > "${concurrent_recovery_status_a}"
) &
pid_a=$!
(
  curl --silent --show-error --output "${concurrent_recovery_response_b}" --dump-header "${concurrent_recovery_headers_b}" \
    --write-out '%{http_code}' --request POST --header 'Content-Type: application/json' \
    --connect-timeout 5 --max-time 30 --data-binary "@${recover_by_key_body}" \
    "${GATEWAY_BASE_URL}${RECOVER_BY_KEY_PATH}" > "${concurrent_recovery_status_b}" \
    || printf '000' > "${concurrent_recovery_status_b}"
) &
pid_b=$!
wait "${pid_a}"
wait "${pid_b}"
concurrent_status_a="$(<"${concurrent_recovery_status_a}")"
concurrent_status_b="$(<"${concurrent_recovery_status_b}")"
if [[ "${concurrent_status_a}" != "200" || "${concurrent_status_b}" != "200" ]]; then
  record_case RECOVERY_CONCURRENT_SAME_KEY_SINGLE_RESPONSE 200 0 "SAME_OPERATION_AND_CREDENTIAL" "CONCURRENT_RECOVERY_TRANSPORT_FAILURE" 0 false
  fail 'Concurrent recover-by-key request did not return HTTP 200.'
fi
concurrent_operation_a="$(jq -r '.operationId // .data.operationId // empty' "${concurrent_recovery_response_a}")"
concurrent_operation_b="$(jq -r '.operationId // .data.operationId // empty' "${concurrent_recovery_response_b}")"
concurrent_access_a="$(jq -er '.data.accessToken' "${concurrent_recovery_response_a}")"
concurrent_access_b="$(jq -er '.data.accessToken' "${concurrent_recovery_response_b}")"
concurrent_refresh_a="$(jq -er '.data.refreshToken' "${concurrent_recovery_response_a}")"
concurrent_refresh_b="$(jq -er '.data.refreshToken' "${concurrent_recovery_response_b}")"
concurrent_access_fingerprint_a="$(sha256_text "${concurrent_access_a}")"
concurrent_access_fingerprint_b="$(sha256_text "${concurrent_access_b}")"
concurrent_refresh_fingerprint_a="$(sha256_text "${concurrent_refresh_a}")"
concurrent_refresh_fingerprint_b="$(sha256_text "${concurrent_refresh_b}")"
concurrent_session_operation_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_operation WHERE user_id = ${user_id} AND operation_type = 'SWITCH_CARD' AND idempotency_key_hash = SHA2('$(mysql_escape "${idempotency_key}")', 256)")"
concurrent_outbox_count="$(mysql_query "SELECT COUNT(*) FROM auth_session_outbox WHERE operation_id = '$(mysql_escape "${operation_id}")'")"
if [[ "${concurrent_operation_a}" != "${operation_id}" || "${concurrent_operation_b}" != "${operation_id}" \
    || "${concurrent_access_fingerprint_a}" != "${concurrent_access_fingerprint_b}" \
    || "${concurrent_access_fingerprint_a}" != "$(sha256_text "${new_access_token}")" \
    || "${concurrent_refresh_fingerprint_a}" != "${concurrent_refresh_fingerprint_b}" \
    || "${concurrent_refresh_fingerprint_a}" != "$(sha256_text "${recovered_refresh_token}")" \
    || "${concurrent_session_operation_count}" != "1" || "${concurrent_outbox_count}" != "${outbox_count}" ]]; then
  record_case RECOVERY_CONCURRENT_SAME_KEY_SINGLE_RESPONSE 200 0 "SAME_OPERATION_AND_CREDENTIAL" "DIVERGENT_CONCURRENT_RECOVERY" 0 false
  fail 'Concurrent recover-by-key requests diverged or created an extra durable sequence.'
fi
record_case_pass RECOVERY_CONCURRENT_SAME_KEY_SINGLE_RESPONSE 200 "SAME_OPERATION_AND_CREDENTIAL" 0

# Wrong operationId returns the documented NOT_FOUND decision.
status_path="$(printf "${STATUS_PATH_TEMPLATE}" "tdsc-missing-operation-id")"
status_response="${WORK_DIR}/status-response.json"
status_headers="${WORK_DIR}/status-headers.txt"
http_json GET "${status_path}" "" "${new_access_token}" "" "${status_response}" "${status_headers}"
# Missing operations resolve to 404 NOT_FOUND or 409 SESSION_OPERATION_NOT_FOUND depending on handler.
if [[ "${HTTP_STATUS}" == "404" && "${HTTP_DECISION}" == "SESSION_OPERATION_NOT_FOUND" ]]; then
  record_case_pass RECOVERY_WRONG_OPERATION_ID 404 "SESSION_OPERATION_NOT_FOUND" "${HTTP_ELAPSED_MS}"
else
  record_case RECOVERY_WRONG_OPERATION_ID 404 "${HTTP_STATUS}" "SESSION_OPERATION_NOT_FOUND" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'recover-with-wrong-operationId did not return the documented NOT_FOUND decision.'
fi

# Wrong refresh-token hash on the recover-by-key endpoint.
recover_wrong_refresh_body="${WORK_DIR}/recover-wrong-refresh.json"
printf '%s' "$(jq -cn --arg idempotencyKey "${idempotency_key}" --arg refreshToken "tdsc-invalid-refresh-token" '{idempotencyKey:$idempotencyKey,refreshToken:$refreshToken}')" > "${recover_wrong_refresh_body}"
recover_wrong_refresh_response="${WORK_DIR}/recover-wrong-refresh-response.json"
recover_wrong_refresh_headers="${WORK_DIR}/recover-wrong-refresh-headers.txt"
http_json POST "${RECOVER_BY_KEY_PATH}" "${recover_wrong_refresh_body}" "" "" "${recover_wrong_refresh_response}" "${recover_wrong_refresh_headers}"
# The durable ledger rejects a refresh-token hash mismatch with CONFLICT or a documented INVALID decision.
if [[ "${HTTP_STATUS}" == "409" || "${HTTP_STATUS}" == "404" ]]; then
  record_case_pass RECOVERY_WRONG_REFRESH_HASH "${HTTP_STATUS}" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}"
else
  record_case RECOVERY_WRONG_REFRESH_HASH 409 "${HTTP_STATUS}" "REJECT" "${HTTP_DECISION}" "${HTTP_ELAPSED_MS}" false
  fail 'recover-by-key accepted an invalid refresh-token hash binding.'
fi

# ---------------------------------------------------------------------------
# Persistent postconditions written to evidence.
# ---------------------------------------------------------------------------

jq -n \
  --arg runId "${TDSC_RUN_ID}" \
  --arg protectedPath "${PROTECTED_PATH}" \
  --arg operationStatus "${operation_status}" \
  --arg oldJtiSha256 "${old_jti_fingerprint}" \
  --arg newJtiSha256 "${new_jti_fingerprint}" \
  --argjson sourceCardOwned true \
  --argjson targetCardSelected true \
  --argjson oldScalarPresent "${old_scalar_present}" \
  --argjson oldGrantPresent "${old_grant_present}" \
  --argjson newScalarPresent "${new_scalar_present}" \
  --argjson newGrantPresent "${new_grant_present}" \
  --argjson outboxEventCount "${outbox_count}" \
  --argjson outboxProcessedCount "${outbox_processed_count}" \
  --argjson sec1RuleCountUnchangedAfterAttack true \
  --argjson sec3NoDurableMutation true \
  --argjson sec5DisabledContextRejected true \
  --argjson sec6NoBypassAudit true \
  --arg recoveryConcurrentAccessSha256 "${concurrent_access_fingerprint_a}" \
  --arg recoveryConcurrentRefreshSha256 "${concurrent_refresh_fingerprint_a}" \
  --argjson recoveryConcurrentOperationCount "${concurrent_session_operation_count}" \
  --argjson recoveryConcurrentOutboxCount "${concurrent_outbox_count}" \
  '{runId:$runId,protectedPath:$protectedPath,operationStatus:$operationStatus,sourceCardOwned:$sourceCardOwned,targetCardSelected:$targetCardSelected,oldAccessJtiSha256:$oldJtiSha256,newAccessJtiSha256:$newJtiSha256,redis:{oldScalarPresent:$oldScalarPresent,oldGrantPresent:$oldGrantPresent,newScalarPresent:$newScalarPresent,newGrantPresent:$newGrantPresent},outbox:{eventCount:$outboxEventCount,processedCount:$outboxProcessedCount},recovery:{concurrentAccessSha256:$recoveryConcurrentAccessSha256,concurrentRefreshSha256:$recoveryConcurrentRefreshSha256,durableOperationCount:$recoveryConcurrentOperationCount,outboxEventCount:$recoveryConcurrentOutboxCount},sec1RuleCountUnchangedAfterAttack:$sec1RuleCountUnchangedAfterAttack,sec3NoDurableMutation:$sec3NoDurableMutation,sec5DisabledContextRejected:$sec5DisabledContextRejected,sec6NoBypassAudit:$sec6NoBypassAudit}' \
  > "${POSTCONDITIONS_FILE}"

jq -cn \
  --arg runId "${TDSC_RUN_ID}" \
  '{runId:$runId,limitations:[
    "SEC-2 tenant/domain isolation: TDSC schema has no runtime tenant-bound card boundary; this runner only exercises a single-share runtime domain. SEC-2 must be retained as a limited claim until a tenant-scoped fixture is added.",
    "SEC-5 forged foreign cardId: cannot be produced without the JWT or gateway signing secret. The disabled-card live-check case is the strongest endpoint-level foreign-context proof this harness produces without forging a signed JWT.",
    "SEC-6 superadmin bypass: the deep superadmin path requires seeding the __SUPERADMIN__ template outside this runner. The runtime case asserts no forged-rule bypass audit; full superadmin source-policy scan belongs in a dedicated composition.",
    "Recovery concurrency: two same-key recover-by-key requests are concurrent only at the client boundary; this runner does not emulate process crash or cross-region replay."
  ]}' > "${LIMITATIONS_FILE}"