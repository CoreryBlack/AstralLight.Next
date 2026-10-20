#!/usr/bin/env bash
#
# Distributed authorization cluster test orchestrator.
#
# Runs the RemoteClusterAuthorizationTest JUnit suite against three independent
# TrustGraph processes (one per node) sharing one MySQL, one Redis and one
# RabbitMQ. Each node is a production boot jar with the test-control plane
# explicitly enabled; the coordinator JVM (where this script runs) drives the
# nodes over HTTP and performs the shared-store assertions.
#
# Fail-closed: every required variable must be provided. Missing input, an
# unreachable node, or a failed probe aborts with an ATTEMPT_ABORTED marker and
# a non-zero exit. Secrets are injected via run-scoped env files with restricted
# permissions, never via command line or logs. Destructive cleanup only happens
# with DIST_TEST_CLEANUP_APPROVED=true.
#
# Two stack modes (DIST_TEST_MODE):
#   java (default)                 deploy JAR_PATH boot jars and drive the run
#                                  with the Java RemoteClusterAuthorizationTest
#                                  coordinator (legacy behavior, unchanged)
#   rust                           deploy a prebuilt Rust astral-trustgraph
#                                  binary and verify readiness with the signed
#                                  Gateway v3 worker-id probe
#                                  (probe_worker_id.py). The Rust node endpoint
#                                  sits behind the full middleware chain
#                                  (Gateway v3 HMAC signature, monitor:read
#                                  authorization, X-Test-Control-Token); no
#                                  SKIP_PATHS or auth bypasses exist or are
#                                  added. No Rust scenario coordinator exists
#                                  yet, so after successful readiness the
#                                  attempt ends BLOCKED (ATTEMPT_ABORTED
#                                  marker) and is never reported PASS.
#
# Two topologies:
#   DIST_TEST_SINGLE_HOST=1        three JVM processes on THIS host + shared
#                                  MySQL/Redis/Rabbit (first validation step)
#   (unset)                        three remote hosts via SSH/SCP (NODE_*_HOST)
#
# Required environment (all of them):
#   DIST_TEST_APPROVED=true
#   DIST_TEST_DB_HOST/PORT/NAME/USER/PASSWORD
#   DIST_TEST_REDIS_HOST/PORT[/PASSWORD][/DATABASE]
#   DIST_TEST_RABBIT_HOST/PORT/USER/PASSWORD
#   TEST_CONTROL_TOKEN
#   DIST_TEST_TEST_GROUP        (e.g. "cluster-remote", java mode only)
#   DIST_TEST_JWT_SECRET        (java mode only; Rust nodes use the two
#                                independent DIST_TEST_JWT_*_SECRET below)
#   DIST_TEST_NODE_A_URL/B/C_URL   base URLs, e.g. http://<NODE_A_HOST>:9011
#   JAR_PATH                     path to the TrustGraph boot jar to deploy
#                                (java mode only)
#   DIST_TEST_SSH_USER           (remote topology only)
#   DIST_TEST_NODE_A_HOST/B_HOST/C_HOST  (remote topology only)
#   DIST_TEST_CLEANUP_APPROVED   only then nodes/shared-store are cleaned
#
# Required additionally in DIST_TEST_MODE=rust (all fail-closed):
#   DIST_TEST_RUST_BIN_PATH      prebuilt astral-trustgraph binary to deploy
#   DIST_TEST_JWT_ACCESS_SECRET  >= 32 chars; written as JWT_ACCESS_SECRET
#   DIST_TEST_JWT_REFRESH_SECRET >= 32 chars; written as JWT_REFRESH_SECRET.
#                                Must be independent of the access secret
#                                (refresh signing material is never shared
#                                with access; no JWT_SECRET alias exists)
#   GATEWAY_HMAC_SECRET          >= 32 chars, same value the Rust nodes run with
#   INTERNAL_SERVICE_SECRET      >= 32 chars (K_LG); independent key, never
#                                derived from or equal to GATEWAY_HMAC_SECRET
#   GATEWAY_INTERNAL_SERVICE_SECRET  >= 32 chars (K_GI); independent key
#   All five secret inputs above must be pairwise distinct and pass the
#   probe-aligned shape check (>= 32 chars; no whitespace/control characters;
#   no case-insensitive placeholder marker, see require_rust_secret);
#   violations abort the attempt before any SSH or node start. astral-common
#   maps these flat
#   names onto their config fields explicitly (apply_flat_env_overrides);
#   nothing relies on config-rs separator inference, and the harness never
#   copies application.yml to a node.
#   DIST_TEST_PROBE_ACTION       must be "read" (GET maps to monitor:read)
#   DIST_TEST_PROBE_PRINCIPAL_KIND   must be PLATFORM_USER
#   DIST_TEST_PROBE_USER_ID / _IDENTITY_CARD_ID / _USER_CARD_ID /
#     _USER_CARD_DOMAIN_ID / _USER_CARD_TENANT_ID
#                                positive integers; the identity must ALREADY
#                                hold a published monitor:read grant in the
#                                shared store (the harness never creates
#                                permissions)
#   DIST_TEST_PROBE_TOKEN_ID / _TOKEN_USE / _CLAIMS_VERSION /
#     _ACTION_CODES / _USER_ROLES
#                                signature-bound text fields (no whitespace)
#
# The dedicated database (schema/migrations and the probe identity's grant)
# must be pre-provisioned by the operator before a rust-mode run; this harness
# never runs migrations and never creates data.
#
# Optional:
#   DIST_TEST_OWNER_NODE         node that runs the startup template/domain
#                               writes (default node-a). Rotate it across
#                               node-a/b/c to prove the safety properties
#                               depend on the architecture, not the hardware
#                               that happens to be the writer.
#   DIST_TEST_ABLATION          one of: generation-fence | l1-eviction |
#                               owner-fence. Runs the RemoteClusterAuthorizationTest
#                               with that mechanism disabled on every node and
#                               executes only the matching ablation test, which
#                               asserts the expected failure appears. Unset for
#                               the baseline run (all mechanisms enabled).
#   DIST_TEST_REPORT_DIR         where the coordinator writes the scenario
#                               reports (default target/cluster-report)

set -euo pipefail

readonly SCRIPT_PROTOCOL_VERSION="dist-authz-3nodes-v2"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
readonly PROJECT_ROOT="$REPO_DIR/AstralLight"
readonly DEFAULT_CAMPAIGN_DIR="$REPO_DIR/Docs/实验/复现运行/dist-cluster-$(date -u +%Y%m%dT%H%M%SZ)"
readonly NODE_IDS=(node-a node-b node-c)
readonly NODE_HOST_VARS=(DIST_TEST_NODE_A_HOST DIST_TEST_NODE_B_HOST DIST_TEST_NODE_C_HOST)
# Non-secret Rust node metadata required by astral-common startup validation
# (issuer/audience must be non-empty in a file-less deployment; CORS must be
# an explicit https origin, never a wildcard). Synthetic, credential-free.
readonly DIST_TEST_RUST_JWT_ACCESS_ISSUER="dist-test-astral-access"
readonly DIST_TEST_RUST_JWT_REFRESH_ISSUER="dist-test-astral-refresh"
readonly DIST_TEST_RUST_JWT_ACCESS_AUDIENCE="dist-test-astral-api"
readonly DIST_TEST_RUST_JWT_REFRESH_AUDIENCE="dist-test-astral-session"
readonly DIST_TEST_RUST_CORS_ALLOWED_ORIGINS="https://dist-test.astral-cluster.invalid"

run_id="${DIST_TEST_RUN_ID:-dist-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
campaign_dir="${DIST_TEST_CAMPAIGN_DIR:-$DEFAULT_CAMPAIGN_DIR}"
owner_node="${DIST_TEST_OWNER_NODE:-node-a}"
ablation_mode="${DIST_TEST_ABLATION:-}"
fault_mode="${DIST_TEST_FAULT_MODE:-synthetic}"
replicate="${DIST_TEST_REPLICATE:-1}"
report_dir="${DIST_TEST_REPORT_DIR:-$PROJECT_ROOT/target/cluster-report}"
single_host="${DIST_TEST_SINGLE_HOST:-0}"
dist_mode="${DIST_TEST_MODE:-java}"
cleanup_approved="${DIST_TEST_CLEANUP_APPROVED:-false}"

cleanup_run_nodes() {
    [[ "$cleanup_approved" == "true" ]] || return 0
    declare -F remote_node_dir >/dev/null 2>&1 || return 0
    local i node_id remote_dir pid_file pid host_var host ssh_user
    for i in 0 1 2; do
        node_id="${NODE_IDS[$i]}"
        remote_dir="$(remote_node_dir "$node_id")"
        if [[ "$single_host" == "1" ]]; then
            pid_file="$campaign_dir/$node_id/node.pid"
            if [[ -f "$pid_file" ]]; then
                pid="$(tr -d '[:space:]' < "$pid_file")"
                if [[ "$pid" =~ ^[0-9]+$ ]]; then
                    kill "$pid" 2>/dev/null || true
                fi
            fi
        elif [[ -n "${DIST_TEST_SSH_USER:-}" ]]; then
            host_var="${NODE_HOST_VARS[$i]}"
            host="${!host_var:-}"
            ssh_user="$(ssh_user_for "$node_id")"
            if [[ -n "$host" && -n "$ssh_user" ]]; then
                ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_user@$host" \
                    "if [[ -f '$remote_dir/node.pid' ]]; then pid=\$(tr -d '[:space:]' < '$remote_dir/node.pid'); if [[ \"\$pid\" =~ ^[0-9]+\$ ]]; then kill \"\$pid\" 2>/dev/null || true; fi; fi" || true
            fi
        fi
    done
}
trap 'cleanup_run_nodes || true' EXIT

if [[ "$campaign_dir" != /* ]]; then
    campaign_dir="$PWD/$campaign_dir"
fi
if [[ "$report_dir" != /* ]]; then
    report_dir="$PROJECT_ROOT/$report_dir"
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | tr -s ' ' | cut -d' ' -f1
    else
        openssl dgst -sha256 -r "$1" | tr -s ' ' | cut -d' ' -f1
    fi
}

# Byte-safe JSON string escaping (pure Bash; deliberately not routed through
# PY_BIN because marker writes can happen before the interpreter is resolved).
#
# The output is guaranteed to be a syntactically valid JSON string body for
# any byte sequence a Bash variable can hold (a NUL byte cannot exist in a
# Bash variable, so it needs no handling):
#   - backslash and double quote are escaped (\\ and \");
#   - LF/CR/TAB keep their short escapes (\n \r \t);
#   - every other C0 byte (0x01-0x1F), DEL (0x7F) and every byte >= 0x80 is
#     emitted as the JSON escape \u00XX (lowercase hex of the raw byte value);
#   - printable ASCII (0x20-0x7E) passes through unchanged.
# Bytes >= 0x80 are escaped by raw byte value rather than decoded as Unicode,
# so even invalid UTF-8 in an operator-controlled reason or in the last
# probe-log line cannot produce an unparseable ATTEMPT_ABORTED.json. The
# input value is never logged.
json_escape() {
    local value="$1" out="" ch esc="" mid_ch="" lo hi mid i
    local LC_ALL=C
    for ((i = 0; i < ${#value}; i++)); do
        ch="${value:i:1}"
        case "$ch" in
            \\) out+='\\' ;;
            '"') out+='\"' ;;
            $'\n') out+='\n' ;;
            $'\r') out+='\r' ;;
            $'\t') out+='\t' ;;
            [$'\x20'-$'\x7e']) out+="$ch" ;;
            *)
                # Byte value via binary search over single-byte comparisons
                # (portable; avoids locale/quoting pitfalls of printf "'$ch").
                # LC_ALL=C above makes [[ < ]] and ${value:i:1} byte-wise.
                lo=0 hi=256
                while ((hi - lo > 1)); do
                    mid=$(((lo + hi) / 2))
                    printf -v mid_ch '%b' \
                        "\\$(((mid >> 6) & 7))$(((mid >> 3) & 7))$((mid & 7))"
                    if [[ "$ch" < "$mid_ch" ]]; then
                        hi=$mid
                    else
                        lo=$mid
                    fi
                done
                printf -v esc '\\u%04x' "$lo"
                out+="$esc"
                ;;
        esac
    done
    printf '%s' "$out"
}

# True when the named variable is currently exported (visible to child
# processes such as the Rust-mode Python probe). The `declare -p` output
# embeds the variable VALUE; it is parsed in place and never printed, logged
# or written anywhere.
shell_var_is_exported() {
    local name="$1" decl attrs
    decl="$(declare -p "$name" 2>/dev/null)" || return 1
    attrs="${decl#declare }"
    attrs="${attrs%% *}"
    [[ "$attrs" == *x* ]]
}

# ---- Rust node connection strings (DIST_TEST_MODE=rust) ------------------
# Rust services read full connection-string URLs (DATABASE_URL / REDIS_URL /
# RABBITMQ_URL). Credentials are percent-encoded with the python3 standard
# library, passed through the process environment (never argv, never logs)
# and only ever land in the 0600 run-scoped node.env file.
rust_database_url() {
    RUST_URL_USER="$DIST_TEST_DB_USER" RUST_URL_PASSWORD="$DIST_TEST_DB_PASSWORD" \
    "${PY_BIN[@]}" - "$DIST_TEST_DB_HOST" "$DIST_TEST_DB_PORT" "$DIST_TEST_DB_NAME" <<'PY'
import os
import sys
import urllib.parse

host, port, name = sys.argv[1:]
user = urllib.parse.quote(os.environ["RUST_URL_USER"], safe="")
password = urllib.parse.quote(os.environ["RUST_URL_PASSWORD"], safe="")
print("mysql://%s:%s@%s:%s/%s" % (user, password, host, port, name))
PY
}

rust_redis_url() {
    RUST_URL_PASSWORD="${DIST_TEST_REDIS_PASSWORD:-}" \
    "${PY_BIN[@]}" - "$DIST_TEST_REDIS_HOST" "$DIST_TEST_REDIS_PORT" "${DIST_TEST_REDIS_DATABASE:-0}" <<'PY'
import os
import sys
import urllib.parse

host, port, database = sys.argv[1:]
password = urllib.parse.quote(os.environ["RUST_URL_PASSWORD"], safe="")
auth = ":%s@" % password if password else ""
print("redis://%s%s:%s/%s" % (auth, host, port, database))
PY
}

rust_rabbitmq_url() {
    RUST_URL_USER="$DIST_TEST_RABBIT_USER" RUST_URL_PASSWORD="$DIST_TEST_RABBIT_PASSWORD" \
    "${PY_BIN[@]}" - "$DIST_TEST_RABBIT_HOST" "$DIST_TEST_RABBIT_PORT" <<'PY'
import os
import sys
import urllib.parse

host, port = sys.argv[1:]
user = urllib.parse.quote(os.environ["RUST_URL_USER"], safe="")
password = urllib.parse.quote(os.environ["RUST_URL_PASSWORD"], safe="")
print("amqp://%s:%s@%s:%s/%%2f" % (user, password, host, port))
PY
}

# SSH user for a node: per-node override (DIST_TEST_NODE_A_SSH_USER, ...)
# falls back to the shared DIST_TEST_SSH_USER. Nodes in a heterogeneous
# cluster may have different login accounts.
ssh_user_for() {
    local node_id="$1"
    local upper
    upper="$(printf '%s' "${node_id#node-}" | tr 'a-z' 'A-Z')"
    local override="DIST_TEST_NODE_${upper}_SSH_USER"
    if [[ -n "${!override:-}" ]]; then
        printf '%s' "${!override}"
    else
        printf '%s' "${DIST_TEST_SSH_USER:-}"
    fi
}

# Terminal-evidence integrity: ATTEMPT_COMPLETE.json / ATTEMPT_ABORTED.json are
# terminal markers and are never overwritten or deleted.
#   1. an existing terminal marker makes any further marker write refuse,
#      including preflight aborts fired before the campaign-dir guard when a
#      caller reuses an explicit DIST_TEST_CAMPAIGN_DIR;
#   2. the commit uses a no-clobber rename (mv -n) plus a hash check, so a
#      concurrent writer cannot be clobbered and our own bytes are verified;
#   3. temporary .tmp files are removed on every refusal/failure path.
commit_terminal_marker() { # <temporary> <marker>
    local temporary="$1" marker="$2" tmp_hash
    tmp_hash="$(sha256_file "$temporary")" || { rm -f "$temporary"; return 1; }
    if ! mv -n "$temporary" "$marker" >/dev/null 2>&1; then
        rm -f "$temporary"
        return 1
    fi
    if [[ -e "$temporary" ]]; then
        # No-clobber rename skipped: a concurrent commit created the terminal
        # marker first. The existing marker stays authoritative; drop our temp.
        rm -f "$temporary"
        return 1
    fi
    [[ -e "$marker" ]] && [[ "$(sha256_file "$marker")" == "$tmp_hash" ]]
}

write_aborted_marker() {
    local reason_value="$1"
    local escaped_reason escaped_run_id
    escaped_reason="$(json_escape "$reason_value")"
    escaped_run_id="$(json_escape "$run_id")"
    if ! mkdir -p "$campaign_dir"; then
        printf 'Distributed cluster test ABORTED (marker directory unavailable): %s\n' "$reason_value" >&2
        return 0
    fi
    local marker="$campaign_dir/ATTEMPT_ABORTED.json"
    local complete_marker="$campaign_dir/ATTEMPT_COMPLETE.json"
    local temporary="$campaign_dir/.ATTEMPT_ABORTED.json.tmp"
    # Prior terminal evidence is authoritative: refuse (without deleting or
    # overwriting anything) and emit only the sanitized reason/status token.
    if [[ -e "$complete_marker" || -e "$marker" ]]; then
        rm -f "$temporary" "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp"
        printf 'Distributed cluster test ABORTED (prior terminal marker preserved, this attempt not recorded): %s\n' "$reason_value" >&2
        return 0
    fi
    local escaped_owner escaped_replicate escaped_fault
    escaped_owner="$(json_escape "$owner_node")"
    escaped_replicate="$(json_escape "$replicate")"
    escaped_fault="$(json_escape "$fault_mode")"
    if ! printf '{\n  "formatVersion": 1,\n  "status": "ABORTED",\n  "protocolVersion": "%s",\n  "runId": "%s",\n  "ownerNode": "%s",\n  "replicate": "%s",\n  "faultMode": "%s",\n  "reason": "%s"\n}\n' \
        "$SCRIPT_PROTOCOL_VERSION" "$escaped_run_id" "$escaped_owner" "$escaped_replicate" "$escaped_fault" "$escaped_reason" > "$temporary"; then
        rm -f "$temporary"
        printf 'Distributed cluster test ABORTED (marker write failed): %s\n' "$reason_value" >&2
        return 0
    fi
    if commit_terminal_marker "$temporary" "$marker"; then
        printf 'Distributed cluster test ABORTED: %s\nMarker: %s\n' "$reason_value" "$marker" >&2
    else
        printf 'Distributed cluster test ABORTED (terminal marker not committed; existing evidence preserved): %s\n' "$reason_value" >&2
    fi
    return 0
}

require_env() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        write_aborted_marker "MISSING_ENV:$name"
        exit 78
    fi
}

# Case-insensitive placeholder markers rejected in the five Rust secrets.
# Mirrors SECRET_PLACEHOLDER_MARKERS in probe_worker_id.py: the Gateway secret
# is enforced by the probe itself, and the shell preflight uses the same
# marker set so a bad value aborts before any SSH or node start instead of
# failing inside the 240s readiness loop. Only tokens are listed here; the
# secret VALUE is never printed, logged or embedded in any marker.
readonly RUST_SECRET_PLACEHOLDER_MARKERS=(
    change-me changeme replace example todo tbd xxxx password test
)

# Fail-closed secret shape checks for the Rust node env contract, aligned
# with probe_worker_id.py (require_env + require_gateway_secret_env): length
# floor of 32, control characters, and case-insensitive placeholder markers.
# Whitespace is rejected outright -- stricter than the probe, which trims
# surrounding whitespace -- because the node sources the raw env value while
# the probe signs with its trimmed copy, so any whitespace would desynchronize
# the two and only fail inside the readiness loop. Only the variable NAME is
# ever printed; the value never reaches argv, markers or logs.
require_rust_secret() {
    local name="$1" value="${!1}" lowered marker
    if [[ "$value" == *[[:space:][:cntrl:]]* ]]; then
        write_aborted_marker "SECRET_HAS_WHITESPACE_OR_CONTROL:$name"
        exit 78
    fi
    if [[ ${#value} -lt 32 ]]; then
        write_aborted_marker "INVALID_SECRET_TOO_SHORT:$name"
        exit 78
    fi
    lowered="${value,,}"
    for marker in "${RUST_SECRET_PLACEHOLDER_MARKERS[@]}"; do
        if [[ "$lowered" == *"$marker"* ]]; then
            write_aborted_marker "SECRET_IS_KNOWN_PLACEHOLDER:$name"
            exit 78
        fi
    done
}

if [[ "${DIST_TEST_APPROVED:-false}" != "true" ]]; then
    write_aborted_marker "DIST_TEST_APPROVED_NOT_SET"
    exit 78
fi

# ---- shared-store contract ----------------------------------------------
require_env DIST_TEST_APPROVED
require_env DIST_TEST_DATA_RESET_APPROVED
if [[ "$DIST_TEST_DATA_RESET_APPROVED" != "true" ]]; then
    write_aborted_marker "DIST_TEST_DATA_RESET_APPROVED_NOT_SET"
    exit 78
fi

# The preflight JUnit initializes the dedicated schema/seed and run lock before
# any TrustGraph boot jar is started.
require_env DIST_TEST_DB_HOST
require_env DIST_TEST_DB_PORT
require_env DIST_TEST_DB_NAME
require_env DIST_TEST_DB_USER
require_env DIST_TEST_DB_PASSWORD
require_env DIST_TEST_REDIS_HOST
require_env DIST_TEST_REDIS_PORT
require_env DIST_TEST_REDIS_DATABASE
require_env DIST_TEST_RABBIT_HOST
require_env DIST_TEST_RABBIT_PORT
require_env DIST_TEST_RABBIT_USER
require_env DIST_TEST_RABBIT_PASSWORD
require_env TEST_CONTROL_TOKEN
if [[ "$dist_mode" == "java" ]]; then
    require_env DIST_TEST_JWT_SECRET
    require_env DIST_TEST_TEST_GROUP
    if [[ "$DIST_TEST_TEST_GROUP" != "cluster-remote" ]]; then
        write_aborted_marker "UNSUPPORTED_TEST_GROUP:$DIST_TEST_TEST_GROUP"
        exit 78
    fi
fi

require_env DIST_TEST_NODE_A_URL
require_env DIST_TEST_NODE_B_URL
require_env DIST_TEST_NODE_C_URL
if [[ "$dist_mode" == "java" ]]; then
    require_env JAR_PATH
else
    require_env DIST_TEST_RUST_BIN_PATH
fi

single_host="${DIST_TEST_SINGLE_HOST:-0}"
if ! [[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
    write_aborted_marker "INVALID_RUN_ID:$run_id"
    exit 78
fi
if ! [[ "${DIST_TEST_REMOTE_ROOT:-/tmp/astral-distributed-test}" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    write_aborted_marker "INVALID_REMOTE_ROOT"
    exit 78
fi

if [[ "$single_host" != "1" ]]; then
    require_env DIST_TEST_SSH_USER
    require_env DIST_TEST_NODE_A_HOST
    require_env DIST_TEST_NODE_B_HOST
    require_env DIST_TEST_NODE_C_HOST
fi

if [[ "$DIST_TEST_DB_NAME" != *"$run_id"* ]]; then
    write_aborted_marker "DB_NAME_MUST_INCLUDE_RUN_ID"
    exit 78
fi
if ! [[ "$DIST_TEST_REDIS_DATABASE" =~ ^[1-9]$|^1[0-5]$ ]]; then
    write_aborted_marker "INVALID_REDIS_DATABASE:$DIST_TEST_REDIS_DATABASE"
    exit 78
fi

case "$owner_node" in
    node-a|node-b|node-c) ;;
    *) write_aborted_marker "INVALID_OWNER_NODE:$owner_node"; exit 78 ;;
esac
case "$ablation_mode" in
    ""|generation-fence|l1-eviction|owner-fence|ab-c) ;;
    *) write_aborted_marker "UNKNOWN_ABLATION_MODE:$ablation_mode"; exit 78 ;;
esac
case "$fault_mode" in
    synthetic|process-crash|redis-restart) ;;
    none) write_aborted_marker "FAULT_MODE_NONE_WOULD_MISLABEL_SYNTHETIC_SCENARIOS"; exit 78 ;;
    *) write_aborted_marker "FAULT_MODE_NOT_IMPLEMENTED:$fault_mode"; exit 78 ;;
esac
if [[ "$replicate" != "1" ]]; then
    write_aborted_marker "REPLICATE_MATRIX_NOT_IMPLEMENTED:$replicate"
    exit 78
fi

case "$dist_mode" in
    java|rust) ;;
    *) write_aborted_marker "INVALID_DIST_TEST_MODE:$dist_mode"; exit 78 ;;
esac
if [[ "$dist_mode" == "rust" ]]; then
    # Java-coordinator-only features must not silently no-op in rust mode.
    [[ -z "$ablation_mode" ]] || { write_aborted_marker "ABLATION_UNSUPPORTED_IN_RUST_MODE"; exit 78; }
    [[ "$fault_mode" == "synthetic" ]] || { write_aborted_marker "FAULT_MODE_UNSUPPORTED_IN_RUST_MODE"; exit 78; }
    [[ -z "${DIST_TEST_EXPERIMENT:-}" ]] || { write_aborted_marker "EXPERIMENT_UNSUPPORTED_IN_RUST_MODE"; exit 78; }
fi

if [[ "$single_host" != "0" && "$single_host" != "1" ]]; then
    write_aborted_marker "INVALID_SINGLE_HOST:$single_host"
    exit 78
fi

if ! [[ "$DIST_TEST_DB_PORT" =~ ^[1-9][0-9]{1,4}$ && "$DIST_TEST_REDIS_PORT" =~ ^[1-9][0-9]{1,4}$ && "$DIST_TEST_RABBIT_PORT" =~ ^[1-9][0-9]{1,4}$ ]]; then
    write_aborted_marker "INVALID_SERVICE_PORT"
    exit 78
fi

for node_url in "$DIST_TEST_NODE_A_URL" "$DIST_TEST_NODE_B_URL" "$DIST_TEST_NODE_C_URL"; do
    if [[ "$node_url" =~ [[:space:][:cntrl:]] || ! "$node_url" =~ ^https?://[^/@#]+(:[0-9]{1,5})?$ ]]; then
        write_aborted_marker "INVALID_NODE_URL"
        exit 78
    fi
done

# ---- Python interpreter resolution ---------------------------------------
# Every Python invocation in this script goes through the PY_BIN array (no
# eval; argument boundaries stay intact). DIST_TEST_PYTHON_BIN wins when it
# is set and usable; otherwise python3, python and finally the Windows
# launcher "py -3" are probed with a standard-library import check. Fail
# closed via the aborted marker when no candidate works.
PY_BIN=()
if [[ -n "${DIST_TEST_PYTHON_BIN:-}" ]] \
    && "${DIST_TEST_PYTHON_BIN}" -c 'import json,hashlib,pathlib,sys' >/dev/null 2>&1; then
    PY_BIN=("${DIST_TEST_PYTHON_BIN}")
elif command -v python3 >/dev/null 2>&1 \
    && python3 -c 'import json,hashlib,pathlib,sys' >/dev/null 2>&1; then
    PY_BIN=(python3)
elif command -v python >/dev/null 2>&1 \
    && python -c 'import json,hashlib,pathlib,sys' >/dev/null 2>&1; then
    PY_BIN=(python)
elif command -v py >/dev/null 2>&1 \
    && py -3 -c 'import json,hashlib,pathlib,sys' >/dev/null 2>&1; then
    PY_BIN=(py -3)
else
    write_aborted_marker "PYTHON_INTERPRETER_UNAVAILABLE"
    exit 78
fi

if [[ "$dist_mode" == "java" ]]; then
    if [[ "$JAR_PATH" != /* ]]; then
        JAR_PATH="$PWD/$JAR_PATH"
    fi
    JAR_PATH="$(cd "$(dirname "$JAR_PATH")" && pwd)/$(basename "$JAR_PATH")"
    if [[ ! -f "$JAR_PATH" ]]; then
        write_aborted_marker "JAR_NOT_FOUND:$JAR_PATH"
        exit 78
    fi
    ARTIFACT_SRC="$JAR_PATH"
    ARTIFACT_REMOTE_NAME="trustgraph-boot.jar"
    NODE_START_CMD='source ./node.env && exec java -jar ./trustgraph-boot.jar'
    REMOTE_PRESTART=""
    LOCAL_COPY_FAIL_MARKER="JAR_COPY_FAILED"
    SCP_FAIL_MARKER="SCP_FAILED"
else
    if [[ "$DIST_TEST_RUST_BIN_PATH" != /* ]]; then
        DIST_TEST_RUST_BIN_PATH="$PWD/$DIST_TEST_RUST_BIN_PATH"
    fi
    DIST_TEST_RUST_BIN_PATH="$(cd "$(dirname "$DIST_TEST_RUST_BIN_PATH")" && pwd)/$(basename "$DIST_TEST_RUST_BIN_PATH")"
    if [[ ! -f "$DIST_TEST_RUST_BIN_PATH" ]]; then
        write_aborted_marker "RUST_BINARY_NOT_FOUND:$DIST_TEST_RUST_BIN_PATH"
        exit 78
    fi
    ARTIFACT_SRC="$DIST_TEST_RUST_BIN_PATH"
    ARTIFACT_REMOTE_NAME="astral-trustgraph"
    NODE_START_CMD='source ./node.env && exec ./astral-trustgraph'
    REMOTE_PRESTART="chmod +x ./$ARTIFACT_REMOTE_NAME && "
    LOCAL_COPY_FAIL_MARKER="RUST_BINARY_COPY_FAILED"
    SCP_FAIL_MARKER="RUST_BINARY_SCP_FAILED"
fi

if [[ "$dist_mode" == "rust" ]]; then
    # Signed probe + node env contract: every input below is required; anything
    # missing or malformed aborts the attempt before any SSH or node start
    # (fail-closed). astral-common maps these flat names explicitly (see
    # apply_flat_env_overrides in astral-common/src/config/mod.rs); the harness
    # never copies application.yml and never relies on config-rs inference.
    require_env GATEWAY_HMAC_SECRET
    require_env DIST_TEST_JWT_ACCESS_SECRET
    require_env DIST_TEST_JWT_REFRESH_SECRET
    require_env INTERNAL_SERVICE_SECRET
    require_env GATEWAY_INTERNAL_SERVICE_SECRET
    require_rust_secret GATEWAY_HMAC_SECRET
    require_rust_secret DIST_TEST_JWT_ACCESS_SECRET
    require_rust_secret DIST_TEST_JWT_REFRESH_SECRET
    require_rust_secret INTERNAL_SERVICE_SECRET
    require_rust_secret GATEWAY_INTERNAL_SERVICE_SECRET
    # Independent keys must never reuse or derive each other (gateway HMAC,
    # K_LG, K_GI, JWT access, JWT refresh); equality is rejected fail-closed.
    if [[ "$GATEWAY_HMAC_SECRET" == "$INTERNAL_SERVICE_SECRET" \
        || "$GATEWAY_HMAC_SECRET" == "$GATEWAY_INTERNAL_SERVICE_SECRET" \
        || "$GATEWAY_HMAC_SECRET" == "$DIST_TEST_JWT_ACCESS_SECRET" \
        || "$GATEWAY_HMAC_SECRET" == "$DIST_TEST_JWT_REFRESH_SECRET" \
        || "$INTERNAL_SERVICE_SECRET" == "$GATEWAY_INTERNAL_SERVICE_SECRET" \
        || "$INTERNAL_SERVICE_SECRET" == "$DIST_TEST_JWT_ACCESS_SECRET" \
        || "$INTERNAL_SERVICE_SECRET" == "$DIST_TEST_JWT_REFRESH_SECRET" \
        || "$GATEWAY_INTERNAL_SERVICE_SECRET" == "$DIST_TEST_JWT_ACCESS_SECRET" \
        || "$GATEWAY_INTERNAL_SERVICE_SECRET" == "$DIST_TEST_JWT_REFRESH_SECRET" \
        || "$DIST_TEST_JWT_ACCESS_SECRET" == "$DIST_TEST_JWT_REFRESH_SECRET" ]]; then
        write_aborted_marker "INDEPENDENT_SECRETS_MUST_BE_DISTINCT"
        exit 78
    fi
    require_env DIST_TEST_PROBE_ACTION
    if [[ "$DIST_TEST_PROBE_ACTION" != "read" ]]; then
        write_aborted_marker "INVALID_PROBE_ACTION:$DIST_TEST_PROBE_ACTION"
        exit 78
    fi
    require_env DIST_TEST_PROBE_PRINCIPAL_KIND
    if [[ "$DIST_TEST_PROBE_PRINCIPAL_KIND" != "PLATFORM_USER" ]]; then
        write_aborted_marker "INVALID_PROBE_PRINCIPAL_KIND:$DIST_TEST_PROBE_PRINCIPAL_KIND"
        exit 78
    fi
    for probe_int_var in DIST_TEST_PROBE_USER_ID DIST_TEST_PROBE_IDENTITY_CARD_ID \
        DIST_TEST_PROBE_USER_CARD_ID DIST_TEST_PROBE_USER_CARD_DOMAIN_ID \
        DIST_TEST_PROBE_USER_CARD_TENANT_ID; do
        require_env "$probe_int_var"
        if ! [[ "${!probe_int_var}" =~ ^[1-9][0-9]{0,17}$ ]]; then
            write_aborted_marker "INVALID_PROBE_ID:$probe_int_var"
            exit 78
        fi
    done
    for probe_text_var in DIST_TEST_PROBE_TOKEN_ID DIST_TEST_PROBE_TOKEN_USE \
        DIST_TEST_PROBE_CLAIMS_VERSION DIST_TEST_PROBE_ACTION_CODES \
        DIST_TEST_PROBE_USER_ROLES; do
        require_env "$probe_text_var"
        if [[ "${!probe_text_var}" =~ [[:space:][:cntrl:]] ]]; then
            write_aborted_marker "INVALID_PROBE_TEXT:$probe_text_var"
            exit 78
        fi
    done
    # Rust nodes consume connection-string URLs; restrict the interpolated
    # host/db components to URL-safe characters (IPv6 literals fail closed).
    if ! [[ "$DIST_TEST_DB_NAME" =~ ^[A-Za-z0-9_]+$ ]]; then
        write_aborted_marker "INVALID_DB_NAME_FOR_RUST_DSN"
        exit 78
    fi
    for rust_host_var in DIST_TEST_DB_HOST DIST_TEST_REDIS_HOST DIST_TEST_RABBIT_HOST; do
        if ! [[ "${!rust_host_var}" =~ ^[A-Za-z0-9._-]+$ ]]; then
            write_aborted_marker "INVALID_RUST_DSN_HOST:$rust_host_var"
            exit 78
        fi
    done
    # The readiness probe is a child process: every variable probe_worker_id.py
    # reads must be exported, not merely set as an unexported shell variable.
    # Failing here -- before any SSH or node start -- beats failing inside the
    # 240s readiness loop. Only the variable NAME is printed; values never
    # reach markers, argv or logs.
    for probe_export_var in GATEWAY_HMAC_SECRET TEST_CONTROL_TOKEN DIST_TEST_PROBE_ACTION \
        DIST_TEST_PROBE_PRINCIPAL_KIND \
        DIST_TEST_PROBE_USER_ID DIST_TEST_PROBE_IDENTITY_CARD_ID \
        DIST_TEST_PROBE_USER_CARD_ID DIST_TEST_PROBE_USER_CARD_DOMAIN_ID \
        DIST_TEST_PROBE_USER_CARD_TENANT_ID \
        DIST_TEST_PROBE_TOKEN_ID DIST_TEST_PROBE_TOKEN_USE \
        DIST_TEST_PROBE_CLAIMS_VERSION DIST_TEST_PROBE_ACTION_CODES \
        DIST_TEST_PROBE_USER_ROLES; do
        require_env "$probe_export_var"
        if ! shell_var_is_exported "$probe_export_var"; then
            write_aborted_marker "PROBE_ENV_NOT_EXPORTED:$probe_export_var"
            exit 78
        fi
    done
fi

remote_node_dir() {
    local node_id="$1"
    if [[ "$single_host" == "1" ]]; then
        printf '%s/%s' "$campaign_dir" "$node_id"
    else
        printf '%s/%s/%s' "${DIST_TEST_REMOTE_ROOT:-/tmp/astral-distributed-test}" "$run_id" "$node_id"
    fi
}

# ---- node deployment ----------------------------------------------------
write_env_var() {
    local file="$1" name="$2" value="$3"
    printf 'export %s=%q\n' "$name" "$value" >> "$file"
}

deploy_to() { # nodeId host port index
    local node_id="$1" host="$2" port="$3" index="$4"
    local remote_dir ssh_user
    remote_dir="$(remote_node_dir "$node_id")"
    local local_node_dir="$campaign_dir/$node_id"
    mkdir -p "$local_node_dir"

    local env_file="$local_node_dir/node.env"
    # Secrets live in a run-scoped env file with restricted permissions; the
    # java process and the coordinator read it, command lines/logs stay clean.
    umask 077
    : > "$env_file"
    if [[ "$dist_mode" == "rust" ]]; then
        # Rust TrustGraph env contract. astral-common maps these flat names
        # onto their config fields explicitly (apply_flat_env_overrides);
        # config-rs would otherwise nest them away from the serde fields and a
        # file-less node would exit during startup validation. Secrets land
        # only in this 0600 env file, never argv/logs; JWT access and refresh
        # signing material are independent inputs (no JWT_SECRET alias).
        write_env_var "$env_file" DATABASE_URL "$(rust_database_url)"
        write_env_var "$env_file" REDIS_URL "$(rust_redis_url)"
        write_env_var "$env_file" RABBITMQ_URL "$(rust_rabbitmq_url)"
        write_env_var "$env_file" JWT_ACCESS_SECRET "$DIST_TEST_JWT_ACCESS_SECRET"
        write_env_var "$env_file" JWT_REFRESH_SECRET "$DIST_TEST_JWT_REFRESH_SECRET"
        # Non-secret profile metadata: issuer/audience must be non-empty for
        # Learn-role startup validation in a file-less deployment.
        write_env_var "$env_file" JWT_ACCESS_ISSUER "$DIST_TEST_RUST_JWT_ACCESS_ISSUER"
        write_env_var "$env_file" JWT_REFRESH_ISSUER "$DIST_TEST_RUST_JWT_REFRESH_ISSUER"
        write_env_var "$env_file" JWT_ACCESS_AUDIENCE "$DIST_TEST_RUST_JWT_ACCESS_AUDIENCE"
        write_env_var "$env_file" JWT_REFRESH_AUDIENCE "$DIST_TEST_RUST_JWT_REFRESH_AUDIENCE"
        write_env_var "$env_file" GATEWAY_HMAC_SECRET "$GATEWAY_HMAC_SECRET"
        write_env_var "$env_file" INTERNAL_SERVICE_SECRET "$INTERNAL_SERVICE_SECRET"
        write_env_var "$env_file" GATEWAY_INTERNAL_SERVICE_SECRET "$GATEWAY_INTERNAL_SERVICE_SECRET"
        # Explicit nonsecret CORS contract: a single synthetic https origin,
        # never a wildcard (wildcard origins are rejected by node validation).
        write_env_var "$env_file" CORS_ALLOWED_ORIGINS "$DIST_TEST_RUST_CORS_ALLOWED_ORIGINS"
        write_env_var "$env_file" CORS_ALLOW_CREDENTIALS false
        write_env_var "$env_file" SESSION_GRANT_CLAIMS_MODE REQUIRE
        # Read outside AppConfig: bind address and the test-control plane.
        write_env_var "$env_file" LISTEN_ADDR "0.0.0.0:$port"
        write_env_var "$env_file" ASTRAL_NODE_ID "$node_id"
        write_env_var "$env_file" ASTRAL_TEST_CONTROL_ENABLED true
        write_env_var "$env_file" ASTRAL_TEST_CONTROL_TOKEN "$TEST_CONTROL_TOKEN"
    else
        write_env_var "$env_file" DB_HOST "$DIST_TEST_DB_HOST"
        write_env_var "$env_file" DB_PORT "$DIST_TEST_DB_PORT"
        write_env_var "$env_file" DB_NAME "$DIST_TEST_DB_NAME"
        write_env_var "$env_file" DB_USERNAME "$DIST_TEST_DB_USER"
        write_env_var "$env_file" DB_PASSWORD "$DIST_TEST_DB_PASSWORD"
        write_env_var "$env_file" SPRING_DATASOURCE_URL "jdbc:mysql://$DIST_TEST_DB_HOST:$DIST_TEST_DB_PORT/$DIST_TEST_DB_NAME?useUnicode=true&characterEncoding=utf8&serverTimezone=UTC"
        write_env_var "$env_file" SPRING_DATASOURCE_USERNAME "$DIST_TEST_DB_USER"
        write_env_var "$env_file" SPRING_DATASOURCE_PASSWORD "$DIST_TEST_DB_PASSWORD"
        write_env_var "$env_file" REDIS_HOST "$DIST_TEST_REDIS_HOST"
        write_env_var "$env_file" REDIS_PORT "$DIST_TEST_REDIS_PORT"
        write_env_var "$env_file" REDIS_PASSWORD "${DIST_TEST_REDIS_PASSWORD:-}"
        write_env_var "$env_file" SPRING_DATA_REDIS_HOST "$DIST_TEST_REDIS_HOST"
        write_env_var "$env_file" SPRING_DATA_REDIS_PORT "$DIST_TEST_REDIS_PORT"
        write_env_var "$env_file" SPRING_DATA_REDIS_PASSWORD "${DIST_TEST_REDIS_PASSWORD:-}"
        write_env_var "$env_file" SPRING_DATA_REDIS_DATABASE "${DIST_TEST_REDIS_DATABASE:-0}"
        write_env_var "$env_file" RABBIT_HOST "$DIST_TEST_RABBIT_HOST"
        write_env_var "$env_file" RABBIT_PORT "$DIST_TEST_RABBIT_PORT"
        write_env_var "$env_file" RABBIT_USERNAME "$DIST_TEST_RABBIT_USER"
        write_env_var "$env_file" RABBIT_PASSWORD "$DIST_TEST_RABBIT_PASSWORD"
        write_env_var "$env_file" SPRING_RABBITMQ_HOST "$DIST_TEST_RABBIT_HOST"
        write_env_var "$env_file" SPRING_RABBITMQ_PORT "$DIST_TEST_RABBIT_PORT"
        write_env_var "$env_file" SPRING_RABBITMQ_USERNAME "$DIST_TEST_RABBIT_USER"
        write_env_var "$env_file" SPRING_RABBITMQ_PASSWORD "$DIST_TEST_RABBIT_PASSWORD"
        write_env_var "$env_file" JWT_SECRET "$DIST_TEST_JWT_SECRET"
        write_env_var "$env_file" SPRING_JWT_SECRET "$DIST_TEST_JWT_SECRET"
        write_env_var "$env_file" SERVER_PORT "$port"
        write_env_var "$env_file" APP_SCHEDULING_ENABLED false
        write_env_var "$env_file" APP_PERMISSION_CONSISTENCY_CHECK_SAMPLE_RATE 0
        write_env_var "$env_file" APP_TEST_CONTROL_ENABLED true
        write_env_var "$env_file" APP_TEST_CONTROL_TOKEN "$TEST_CONTROL_TOKEN"
        write_env_var "$env_file" APP_NODE_OWNER "$([[ "$node_id" == "$owner_node" ]] && printf true || printf false)"
        write_env_var "$env_file" JAVA_TOOL_OPTIONS "-Dbenchmark.cluster.node-id=$node_id"
        write_env_var "$env_file" SPRING_JWT_SECRET "$DIST_TEST_JWT_SECRET"
        write_env_var "$env_file" SPRING_JWT_SECRET_KEY "$DIST_TEST_JWT_SECRET"
        write_env_var "$env_file" APP_MESSAGING_PERMISSION_REFRESH_QUEUE "astral.permission.refresh.$run_id.$node_id"
        write_env_var "$env_file" APP_MESSAGING_PERMISSION_REFRESH_DLX_QUEUE "astral.dlx.permission.refresh.$run_id.$node_id"
        write_env_var "$env_file" APP_MESSAGING_REFRESH_RECEIPT_PREFIX "cluster:refresh:receipt:$run_id:$node_id:"
        write_env_var "$env_file" SPRING_DATA_REDIS_DATABASE "${DIST_TEST_REDIS_DATABASE:-0}"
    fi
    write_env_var "$env_file" DIST_TEST_RUN_ID "$run_id"
    write_env_var "$env_file" DIST_TEST_REPLICATE "$replicate"
    write_env_var "$env_file" DIST_TEST_FAULT_MODE "$fault_mode"
    chmod 600 "$env_file"

    # Ablation runs disable exactly one mechanism on every node so the failure
    # it prevents becomes observable; the baseline run leaves all switches off.
    if [[ -n "$ablation_mode" ]]; then
        case "$ablation_mode" in
            generation-fence)
                write_env_var "$env_file" APP_AUTHORIZATION_PROJECTION_ABLATION_SKIP_WORKER_GENERATION_FENCE true
                ;;
            l1-eviction)
                write_env_var "$env_file" APP_AUTHORIZATION_PROJECTION_ABLATION_SKIP_L1_REFS_STATUS_EVICTION true
                ;;
            owner-fence)
                write_env_var "$env_file" APP_AUTHORIZATION_PROJECTION_ABLATION_SKIP_OWNER_FENCE true
                ;;
            ab-c)
                write_env_var "$env_file" APP_MESSAGING_ABLATION_SKIP_PUBLISHER_CONFIRM true
                ;;
        esac
        printf 'Ablation mode %s enabled for node %s\n' "$ablation_mode" "$node_id"
    fi
    chmod 600 "$env_file"

    if [[ "$single_host" == "1" ]]; then
        printf 'Deploying node %s (single-host, port %s)\n' "$node_id" "$port"
        cp "$ARTIFACT_SRC" "$remote_dir/$ARTIFACT_REMOTE_NAME" || {
            write_aborted_marker "$LOCAL_COPY_FAIL_MARKER:$node_id"; exit 78; }
        if [[ "$dist_mode" == "rust" ]]; then
            chmod +x "$remote_dir/$ARTIFACT_REMOTE_NAME"
        fi
        (
            cd "$remote_dir"
            nohup bash -c "$NODE_START_CMD" \
                > node.log 2>&1 < /dev/null &
            pid=$!
            sleep 1
            kill -0 "$pid" 2>/dev/null
            printf '%s\n' "$pid" > node.pid
        )
    else
        printf 'Deploying node %s to %s:%s\n' "$node_id" "$host" "$port"
        ssh_user="$(ssh_user_for "$node_id")"
        ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_user@$host" "mkdir -p '$remote_dir'" || {
            write_aborted_marker "SSH_MKDIR_FAILED:$node_id"; exit 78; }
        scp -o BatchMode=yes -o ConnectTimeout=10 "$ARTIFACT_SRC" "$ssh_user@$host:$remote_dir/$ARTIFACT_REMOTE_NAME" || {
            write_aborted_marker "$SCP_FAIL_MARKER:$node_id"; exit 78; }
        scp -o BatchMode=yes -o ConnectTimeout=10 "$env_file" "$ssh_user@$host:$remote_dir/node.env" || {
            write_aborted_marker "SCP_ENV_FAILED:$node_id"; exit 78; }
        ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_user@$host" \
            "cd '$remote_dir' && chmod 600 node.env && ${REMOTE_PRESTART}( setsid bash -c \"$NODE_START_CMD\" > node.log 2>&1 < /dev/null & echo \$! > node.pid ) && sleep 3 && kill -0 \$(cat node.pid) 2>/dev/null && exit 0" || {
            write_aborted_marker "SSH_START_FAILED:$node_id"; exit 78; }
    fi
}

wait_ready_rust() { # nodeId url
    local node_id="$1" url="$2"
    # The probe is a child process: export exactly the variables
    # probe_worker_id.py requires (and nothing else) immediately before
    # invocation, so the probe inherits them even if an earlier assignment
    # left them unexported. Values travel only through the process
    # environment -- never argv, never logs. All other credentials (JWT
    # access/refresh, K_LG, K_GI, DB/Redis/Rabbit) are NOT exported by this
    # script; within the harness they land only in the 0600 node env file
    # (values the caller itself exports are inherited by this script and
    # cannot be hidden here). Missing/invalid/unexported values
    # already fail closed in preflight (MISSING_ENV / PROBE_ENV_NOT_EXPORTED).
    export GATEWAY_HMAC_SECRET TEST_CONTROL_TOKEN DIST_TEST_PROBE_ACTION \
        DIST_TEST_PROBE_PRINCIPAL_KIND \
        DIST_TEST_PROBE_USER_ID DIST_TEST_PROBE_IDENTITY_CARD_ID \
        DIST_TEST_PROBE_USER_CARD_ID DIST_TEST_PROBE_USER_CARD_DOMAIN_ID \
        DIST_TEST_PROBE_USER_CARD_TENANT_ID \
        DIST_TEST_PROBE_TOKEN_ID DIST_TEST_PROBE_TOKEN_USE \
        DIST_TEST_PROBE_CLAIMS_VERSION DIST_TEST_PROBE_ACTION_CODES \
        DIST_TEST_PROBE_USER_ROLES
    local probe_url="$url/main/api/v1/internal/test-control/worker-id"
    local probe_log="$campaign_dir/$node_id/probe.log"
    local deadline=$((SECONDS + 240))
    while (( SECONDS < deadline )); do
        # Signed Gateway v3 probe: sends X-Gateway-Auth/Ts/Signature plus the
        # test-control token; secrets stay in the probe process environment,
        # the probe log holds only sanitized reason tokens / non-sensitive
        # identity JSON. Polling deadline and per-attempt timeout are bounded.
        if "${PY_BIN[@]}" "$SCRIPT_DIR/probe_worker_id.py" \
                --url "$probe_url" \
                --node-id "$node_id" \
                --request-id "$run_id:$node_id" \
                > "$probe_log" 2>&1; then
            printf 'Node %s ready (rust signed Gateway v3 probe): %s\n' "$node_id" "$url"
            return 0
        fi
        sleep 2
    done
    write_aborted_marker "NODE_NOT_READY:$node_id:$(tail -n 1 "$probe_log" 2>/dev/null || printf 'NO_PROBE_REASON')"
    return 78
}

wait_ready() { # nodeId url
    local node_id="$1" url="$2"
    if [[ "$dist_mode" == "rust" ]]; then
        wait_ready_rust "$node_id" "$url"
        return
    fi
    local body
    local response_file
    local token_file
    response_file="$(mktemp)"
    token_file="$(mktemp)"
    umask 077
    printf 'X-Test-Control-Token: %s\n' "$TEST_CONTROL_TOKEN" > "$token_file"
    trap 'rm -f "$response_file" "$token_file"' RETURN
    local deadline=$((SECONDS + 240))
    while (( SECONDS < deadline )); do
        if curl -fsS -m 5 -H "@$token_file" \
                "$url/main/api/v1/internal/test-control/worker-id" > "$response_file" 2>/dev/null \
                && body="$(cat "$response_file")" \
                && "${PY_BIN[@]}" - "$node_id" "$body" <<'PY'
import json
import sys
expected, raw = sys.argv[1:]
value = json.loads(raw)
if value.get("nodeId") != expected:
    raise SystemExit(1)
for field in ("workerId", "configFingerprint"):
    if not isinstance(value.get(field), str) or not value[field] or value[field] == "null":
        raise SystemExit(1)
PY
        then
            printf 'Node %s ready: %s\n' "$node_id" "$url"
            return 0
        fi
        sleep 2
    done
    write_aborted_marker "NODE_NOT_READY:$node_id"
    return 78
}

# Copies the scenario reports (invariants, evidence chain, convergence windows)
# produced by the coordinator into the campaign dir and prepares the comma
# separated report_list for the COMPLETE marker.
collect_reports() {
    local source_dir="$report_dir"
    report_list=""
    if [[ -d "$source_dir" ]]; then
        mkdir -p "$campaign_dir/reports"
        local first=1
        local report
        for report in "$source_dir"/*.json; do
            [[ -e "$report" ]] || continue
            cp "$report" "$campaign_dir/reports/"
            local name
            name="$(basename "$report")"
            if [[ $first -eq 1 ]]; then
                report_list="\"reports/$name\""
                first=0
            else
                report_list="$report_list, \"reports/$name\""
            fi
        done
    fi
    printf 'Collected scenario reports into %s/reports\n' "$campaign_dir"
}

# ---- main ---------------------------------------------------------------
if [[ -e "$campaign_dir" ]]; then
    if [[ -s "$campaign_dir/ATTEMPT_COMPLETE.json" || -s "$campaign_dir/ATTEMPT_ABORTED.json" ]]; then
        printf 'Distributed cluster test ABORTED: campaign directory already contains a terminal marker: %s\n' "$campaign_dir" >&2
    else
        printf 'Distributed cluster test ABORTED: campaign directory already exists: %s\n' "$campaign_dir" >&2
    fi
    exit 78
fi
mkdir -p "$campaign_dir"
report_dir="$report_dir/$run_id"
if [[ -e "$report_dir" ]]; then
    write_aborted_marker "REPORT_RUN_DIRECTORY_ALREADY_EXISTS:$report_dir"
    exit 78
fi
mkdir -p "$report_dir"

# ---- fault-mode setup ----------------------------------------------------
fault_marker_dir="$campaign_dir/fault"
if [[ "$fault_mode" != "synthetic" ]]; then
    mkdir -p "$fault_marker_dir"
    export DIST_TEST_FAULT_MARKER_DIR="$fault_marker_dir"
    if [[ "$fault_mode" == "redis-restart" ]]; then
        redis_container="${DIST_TEST_REDIS_DEDICATED_CONTAINER:-astral_dist_redis_$run_id}"
        export REDIS_DEDICATED_CONTAINER="$redis_container"
        # The dedicated container is exposed on its own port; the shared
        # benchmark Redis (astral_bench_redis) is never touched.
        if [[ -n "${DIST_TEST_REDIS_DEDICATED_PORT:-}" ]]; then
            export DIST_TEST_REDIS_PORT="$DIST_TEST_REDIS_DEDICATED_PORT"
        else
            export DIST_TEST_REDIS_PORT="6383"
        fi
        if ! docker inspect "$redis_container" >/dev/null 2>&1; then
            if ! docker run -d --name "$redis_container" -p "${DIST_TEST_REDIS_PORT}:6379" \
                    redis:7 redis-server --save "" --appendonly no >/dev/null 2>&1; then
                write_aborted_marker "DEDICATED_REDIS_CREATE_FAILED:$redis_container"
                exit 78
            fi
        fi
        redis_healthy_deadline=$(( $(date +%s) + 120 ))
        while (( $(date +%s) < redis_healthy_deadline )); do
            if docker exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG; then
                break
            fi
            sleep 2
        done
        if ! docker exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG; then
            write_aborted_marker "DEDICATED_REDIS_NOT_HEALTHY:$redis_container"
            exit 78
        fi
        # Remove the run-scoped container on exit (approved cleanup only), so
        # repeated fault runs do not accumulate containers or occupy the port.
        cleanup_dedicated_redis() {
            [[ "$cleanup_approved" == "true" ]] || return 0
            [[ -n "${redis_container:-}" ]] || return 0
            docker rm -f "$redis_container" >/dev/null 2>&1 || true
        }
        trap 'cleanup_run_nodes || true; cleanup_dedicated_redis || true' EXIT
    fi
fi

# Export the final attempt metadata before any JUnit fork (including the
# schema preflight), so coordinator and node processes use the same identity.
# Java mode only: rust mode has no JUnit coordinator and no schema-preflight
# fork, so this shared-store export block must not fire there -- Rust nodes
# read all credentials from their 0600 node.env file and the only variables
# this script adds to the probe child's environment are the 14 probe names
# exported in wait_ready_rust. Keeping the DB/Redis/Rabbit credentials and
# other shared-store variables unexported in rust mode is what keeps this
# script from newly broad-exporting them (values the caller itself exports
# are inherited and outside this script's control; see README); the identical
# export block after the rust BLOCKED exit below stays authoritative for the
# Java coordinator run.
if [[ "$dist_mode" == "java" ]]; then
    export DIST_TEST_APPROVED DIST_TEST_DATA_RESET_APPROVED
    export DIST_TEST_DB_HOST DIST_TEST_DB_PORT DIST_TEST_DB_NAME DIST_TEST_DB_USER DIST_TEST_DB_PASSWORD
    export DIST_TEST_REDIS_HOST DIST_TEST_REDIS_PORT DIST_TEST_REDIS_PASSWORD DIST_TEST_REDIS_DATABASE
    export DIST_TEST_RABBIT_HOST DIST_TEST_RABBIT_PORT DIST_TEST_RABBIT_USER DIST_TEST_RABBIT_PASSWORD
    export TEST_CONTROL_TOKEN
    export DIST_TEST_NODE_A_URL DIST_TEST_NODE_B_URL DIST_TEST_NODE_C_URL
    export DIST_TEST_RUN_ID DIST_TEST_OWNER_NODE DIST_TEST_FAULT_MODE DIST_TEST_REPLICATE DIST_TEST_SINGLE_HOST
    export DIST_TEST_ABLATION
    export DIST_TEST_EXPERIMENT
    export DIST_TEST_NETEM_APPROVED DIST_TEST_NETEM_HOST DIST_TEST_NETEM_INTERFACE DIST_TEST_NETEM_DELAY DIST_TEST_NETEM_LEDGER
    export DIST_TEST_FAULT_MARKER_DIR
fi

# Initialize schema/seed before node deployment. This is a destructive,
# explicitly approved preflight and is intentionally separate from the node JVMs.
# The selector runs against AstralTrustGraph only: with -am every upstream module
# would receive -Dtest=RemoteClusterSchemaPreflightTest and fail "no tests match".
# Dependencies are installed beforehand by the caller (mvn install -DskipTests).
# Java-mode only: in rust mode the operator pre-provisions the dedicated
# database; this harness never runs migrations (see README).
if [[ "$dist_mode" == "java" ]]; then
    preflight_args=(mvn -f "$PROJECT_ROOT/pom.xml" -pl AstralTrustGraph
        -Dremote.test=true -Dtest=RemoteClusterSchemaPreflightTest
        -Dsurefire.failIfNoSpecifiedTests=true -Dsurefire.excluded.groups= -DexcludedGroups= -Ddist.test.run.id="$run_id")
    if "${preflight_args[@]}" test > "$campaign_dir/schema-preflight.log" 2>&1; then
        :
    else
        status=$?
        write_aborted_marker "SCHEMA_PREFLIGHT_FAILED"
        exit "$status"
    fi
fi

node_ports=(9011 9012 9013)
for i in 0 1 2; do
    host_var="${NODE_HOST_VARS[$i]}"
    deploy_to "${NODE_IDS[$i]}" "${!host_var:-localhost}" "${node_ports[$i]}" "$i"
done

node_urls=("$DIST_TEST_NODE_A_URL" "$DIST_TEST_NODE_B_URL" "$DIST_TEST_NODE_C_URL")
if [[ "$single_host" == "1" ]]; then
    for index in 0 1 2; do
        expected_port=$((9011 + index))
        if [[ ! "${node_urls[$index]}" =~ ^https?://(localhost|127\.0\.0\.1):$expected_port$ ]]; then
            write_aborted_marker "SINGLE_HOST_URL_MISMATCH:${NODE_IDS[$index]}"
            exit 78
        fi
    done
fi
for i in 0 1 2; do
    wait_ready "${NODE_IDS[$i]}" "${node_urls[$i]}" || exit 78
done

if [[ "$dist_mode" == "rust" ]]; then
    # Node-independence evidence: three separate processes must report three
    # distinct workerId values (per-process restart nonce).
    if ! "${PY_BIN[@]}" - "$campaign_dir" <<'PY'
import json
import pathlib
import sys

base = pathlib.Path(sys.argv[1])
worker_ids = {}
for node in ("node-a", "node-b", "node-c"):
    lines = [
        line
        for line in (base / node / "probe.log").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary = json.loads(lines[-1])
    worker_ids[node] = summary["workerId"]
if len(set(worker_ids.values())) != len(worker_ids):
    raise SystemExit(1)
PY
    then
        write_aborted_marker "NODE_WORKER_ID_NOT_DISTINCT"
        exit 78
    fi
    printf 'Rust node independence: three distinct workerId values observed.\n'
    # No Rust scenario coordinator exists yet (the Java
    # RemoteClusterAuthorizationTest suite is the only scenario driver).
    # Per the evidence contract this attempt is BLOCKED, never PASS:
    # record the terminal marker and stop before any scenario would run.
    write_aborted_marker "RUST_SCENARIO_COORDINATOR_NOT_IMPLEMENTED"
    exit 78
fi

# Run the JUnit suite from the coordinator; the schema/seed initialization and
# fixture resets are driven by RemoteClusterAuthorizationTest against the
# shared store.
export DIST_TEST_APPROVED DIST_TEST_DATA_RESET_APPROVED
export DIST_TEST_DB_HOST DIST_TEST_DB_PORT DIST_TEST_DB_NAME DIST_TEST_DB_USER DIST_TEST_DB_PASSWORD
export DIST_TEST_REDIS_HOST DIST_TEST_REDIS_PORT DIST_TEST_REDIS_PASSWORD DIST_TEST_REDIS_DATABASE
export DIST_TEST_RABBIT_HOST DIST_TEST_RABBIT_PORT DIST_TEST_RABBIT_USER DIST_TEST_RABBIT_PASSWORD
export TEST_CONTROL_TOKEN
export DIST_TEST_NODE_A_URL DIST_TEST_NODE_B_URL DIST_TEST_NODE_C_URL
export DIST_TEST_RUN_ID DIST_TEST_OWNER_NODE DIST_TEST_FAULT_MODE DIST_TEST_REPLICATE DIST_TEST_SINGLE_HOST
export DIST_TEST_ABLATION
export DIST_TEST_EXPERIMENT
export DIST_TEST_NETEM_APPROVED DIST_TEST_NETEM_HOST DIST_TEST_NETEM_INTERFACE DIST_TEST_NETEM_DELAY DIST_TEST_NETEM_LEDGER
export DIST_TEST_FAULT_MARKER_DIR

# The ablation run executes only the test whose expected failure matches the
# disabled mechanism; the baseline run executes the whole class (all scenarios).
mvn_args=(mvn -f "$PROJECT_ROOT/pom.xml" -pl AstralTrustGraph -Dremote.test=true)
mvn_args+=(-Dsurefire.failIfNoSpecifiedTests=true -Dsurefire.excluded.groups= -DexcludedGroups= -Dgroups="$DIST_TEST_TEST_GROUP")
mvn_args+=(-Ddist.test.report.dir="$report_dir" -Ddist.test.run.id="$run_id")
if [[ -n "$ablation_mode" ]]; then
    case "$ablation_mode" in
        generation-fence) mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#ablationGenerationFenceObservedFailure') ;;
        l1-eviction)      mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#ablationL1EvictionObservedFailure') ;;
        owner-fence)      mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#ablationOwnerFenceObservedFailure') ;;
        ab-c)             mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#ablationPublisherConfirmObservedFailure') ;;
        *) write_aborted_marker "UNKNOWN_ABLATION_MODE:$ablation_mode"; exit 78 ;;
    esac
elif [[ "${DIST_TEST_EXPERIMENT:-}" == "cs-distributed" ]]; then
    mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#cs1RevokeFenceBlocksAllowAcrossNodes+cs2SourceOracleMatchesProjectedAcrossNodes+cs3NewGrantProjectionGateAcrossNodes+cs4OverlayDenyPrecedenceAcrossNodes+cs5GenerationSupersessionAcrossNodes+cs6RuleSetUnbindFenceAcrossNodes+cs7TargetResourceIsolationAcrossNodes+cs8WriteAliasSemanticsAcrossNodes')
elif [[ "$fault_mode" == "process-crash" ]]; then
    mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#processCrashMidRevokeNeverResurrectsStaleAllow')
elif [[ "$fault_mode" == "redis-restart" ]]; then
    mvn_args+=(-Dtest='RemoteClusterAuthorizationTest#redisRestartMidRevokeNeverResurrectsStaleAllow')
else
    mvn_args+=(-Dtest=RemoteClusterAuthorizationTest)
fi

# Launch the coordinator JUnit in the background so the fault-injection loop can
# coordinate with its marker protocol; wait below captures the exit status.
"${mvn_args[@]}" test > "$campaign_dir/junit.log" 2>&1 &
coordinator_pid=$!

if [[ "$fault_mode" != "synthetic" ]]; then
    # Real-fault injection loop: coordinate with the coordinator's marker
    # protocol. The coordinator JUnit waits on markers; this loop performs the
    # actual kill/restart or container stop/start and writes the ack.
    (
      set -euo pipefail
      if [[ "$fault_mode" == "process-crash" ]]; then
        while :; do
          [[ -f "$fault_marker_dir/process-crash-requested" ]] && break
          kill -0 "$coordinator_pid" 2>/dev/null || exit 1
          sleep 2
        done
        crashed_node="$(cat "$fault_marker_dir/process-crash-requested" | awk '{print $2}')"
        [[ "$crashed_node" == node-a || "$crashed_node" == node-b || "$crashed_node" == node-c ]] || exit 78
        node_index=$([ "$crashed_node" = node-a ] && echo 0 || [ "$crashed_node" = node-b ] && echo 1 || echo 2)
        host_var="${NODE_HOST_VARS[$node_index]}"
        host="${!host_var:-localhost}"
        ssh_user="$(ssh_user_for "$crashed_node")"
        remote_dir="$(remote_node_dir "$crashed_node")"
        if [[ "$single_host" == "1" ]]; then
          pid="$(tr -d '[:space:]' < "$remote_dir/node.pid")"
          kill "$pid" 2>/dev/null || true
        else
          ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_user@$host" \
            "if [[ -f '$remote_dir/node.pid' ]]; then pid=\$(tr -d '[:space:]' < '$remote_dir/node.pid'); kill \"\$pid\" 2>/dev/null || true; fi" || true
        fi
        # Restart the node from the same env file with a fresh pidfile.
        if [[ "$single_host" == "1" ]]; then
          ( cd "$remote_dir" && nohup bash -c 'source ./node.env && exec java -jar ./trustgraph-boot.jar' > node-restart.log 2>&1 < /dev/null & pid=$!; sleep 1; kill -0 "$pid" 2>/dev/null; printf '%s\n' "$pid" > node.pid )
        else
          ssh -o BatchMode=yes -o ConnectTimeout=10 "$ssh_user@$host" \
            "cd '$remote_dir' && ( setsid bash -c 'source ./node.env && exec java -jar ./trustgraph-boot.jar' > node-restart.log 2>&1 < /dev/null & echo \$! > node.pid ) && sleep 3 && kill -0 \$(cat node.pid) 2>/dev/null" || true
        fi
        printf 'restarted\n' > "$fault_marker_dir/process-crash-ack"
      elif [[ "$fault_mode" == "redis-restart" ]]; then
        while :; do
          [[ -f "$fault_marker_dir/redis-down-requested" ]] && break
          kill -0 "$coordinator_pid" 2>/dev/null || exit 1
          sleep 2
        done
        docker stop "$redis_container" >/dev/null 2>&1 || true
        printf 'down\n' > "$fault_marker_dir/redis-down-ack"
        while :; do
          [[ -f "$fault_marker_dir/redis-restart-requested" ]] && break
          kill -0 "$coordinator_pid" 2>/dev/null || exit 1
          sleep 2
        done
        docker start "$redis_container" >/dev/null 2>&1 || true
        deadline=$(( $(date +%s) + 120 ))
        while (( $(date +%s) < deadline )); do
          docker exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG && break
          sleep 2
        done
        docker exec "$redis_container" redis-cli ping 2>/dev/null | grep -q PONG || exit 78
        printf 'restarted\n' > "$fault_marker_dir/redis-restart-ack"
      fi
    ) &
    fault_loop_pid=$!
    status=0
    wait "$coordinator_pid" || status=$?
    kill "$fault_loop_pid" 2>/dev/null || true
    wait "$fault_loop_pid" 2>/dev/null || true
else
    status=0
    wait "$coordinator_pid" || status=$?
fi
if [[ $status -eq 0 ]]; then
    collect_reports
    report_file="$campaign_dir/reports/invariants-$run_id.json"
    validation_file="$campaign_dir/validation.json"
        if [[ ! -s "$report_file" ]]; then
            status=79
            write_aborted_marker "REPORT_MISSING:$report_file"
        else
            validator_args=("${PY_BIN[@]}" "$SCRIPT_DIR/validate_cluster_report.py"
        --report "$report_file" --run-id "$run_id"
        --owner "$owner_node" --replicate "$replicate" --fault-mode "$fault_mode"
        --mode "$([[ -n "$ablation_mode" ]] && printf ablation || ([[ "$fault_mode" != "synthetic" ]] && printf fault || ([[ "${DIST_TEST_EXPERIMENT:-}" == "cs-distributed" ]] && printf cs-distributed || printf positive)))")
    if [[ -n "$ablation_mode" ]]; then
        validator_args+=(--ablation "$ablation_mode")
    fi
    validator_args+=(--output "$validation_file")
    if "${validator_args[@]}"; then
        report_sha256="$(sha256_file "$report_file")"
        validation_sha256="$(sha256_file "$validation_file")"
        artifact_sha256="$(sha256_file "$ARTIFACT_SRC")"
        # Same terminal-evidence integrity as the ABORTED marker: commit via
        # no-clobber rename, never overwrite existing terminal evidence, and
        # clean the temporary file on refusal/failure.
        if printf '{\n  "formatVersion": 1,\n  "status": "COMPLETE",\n  "protocolVersion": "%s",\n  "runId": "%s",\n  "ownerNode": "%s",\n  "replicate": "%s",\n  "faultMode": "%s",\n  "ablation": "%s",\n  "reportPaths": [%s],\n  "reportSha256": "%s",\n  "validationPath": "validation.json",\n  "validationSha256": "%s",\n  "jarSha256": "%s"\n}\n' \
            "$SCRIPT_PROTOCOL_VERSION" "$run_id" "$owner_node" "$replicate" "$fault_mode" "${ablation_mode:-none}" "$report_list" \
            "$report_sha256" "$validation_sha256" "$artifact_sha256" \
            > "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp" \
            && commit_terminal_marker "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp" "$campaign_dir/ATTEMPT_COMPLETE.json"; then
            printf 'Distributed cluster test PASSED validation. Marker: %s\n' "$campaign_dir/ATTEMPT_COMPLETE.json"
        else
            rm -f "$campaign_dir/.ATTEMPT_COMPLETE.json.tmp"
            status=79
            write_aborted_marker "COMPLETE_MARKER_WRITE_FAILED"
        fi
    else
        status=79
        write_aborted_marker "INVALID_REPORT"
    fi
    fi
else
    write_aborted_marker "JUNIT_FAILED"
fi

# Cleanup is handled by the EXIT trap so preflight, deployment, readiness and
# JUnit failures all use the same run-scoped cleanup path.
exit "$status"
