#!/usr/bin/env bash
# Linux-only, fail-closed network delay harness for the distributed authorization campaign.
# It applies a run-scoped tc/netem delay to one interface and always attempts to
# remove the qdisc before returning. It never starts a campaign by itself.
#
# The qdisc can be applied on the local host or, when DIST_TEST_NETEM_HOST is set,
# on a remote host via SSH (the remote command runs under `sudo -n`, so the remote
# user must have NOPASSWD sudo). The wrapped campaign command always runs locally.
set -euo pipefail

run_id="${DIST_TEST_RUN_ID:-}"
interface="${DIST_TEST_NETEM_INTERFACE:-}"
delay="${DIST_TEST_NETEM_DELAY:-200ms}"
jitter="${DIST_TEST_NETEM_JITTER:-50ms}"
loss="${DIST_TEST_NETEM_LOSS:-}"
reorder="${DIST_TEST_NETEM_REORDER:-}"
target_node="${DIST_TEST_NETEM_TARGET_NODE:-}"
netem_host="${DIST_TEST_NETEM_HOST:-}"
netem_user="${DIST_TEST_NETEM_USER:-}"
if [[ -z "${DIST_TEST_NETEM_LEDGER:-}" ]]; then
    ledger="${PWD}/network-fault-${run_id:-unknown}.json"
else
    ledger="$DIST_TEST_NETEM_LEDGER"
fi
if [[ "$ledger" != /* ]]; then
    ledger="$PWD/$ledger"
fi
if [[ "$ledger" == *".."* || "$ledger" == *$'\n'* ]]; then
    printf 'invalid ledger path\n' >&2
    exit 78
fi

# Run a tc command locally, or on the remote target host via sudo -n SSH.
tc_run() {
    if [[ -n "$netem_host" ]]; then
        ssh -o BatchMode=yes -o ConnectTimeout=10 "$netem_user@$netem_host" "sudo -n $*"
    else
        "$@"
    fi
}

write_ledger() {
    local status="$1" reason="$2"
    mkdir -p "$(dirname "$ledger")"
    printf '{\n  "runId": "%s",\n  "mode": "tc-netem-delay",\n  "targetNode": "%s",\n  "targetHost": "%s",\n  "interface": "%s",\n  "delay": "%s",\n  "jitter": "%s",\n  "loss": "%s",\n  "reorder": "%s",\n  "status": "%s",\n  "reason": "%s",\n  "ledgerPath": "%s"\n}\n' \
        "$run_id" "$target_node" "$netem_host" "$interface" "$delay" "$jitter" "${loss:-none}" "${reorder:-none}" "$status" "$reason" "$ledger" > "${ledger}.tmp"
    mv -f "${ledger}.tmp" "$ledger"
}

if [[ "${DIST_TEST_APPROVED:-false}" != "true" ]]; then
    write_ledger ABORTED DIST_TEST_APPROVED_NOT_SET
    exit 78
fi
if [[ "${DIST_TEST_NETEM_APPROVED:-false}" != "true" ]]; then
    write_ledger ABORTED DIST_TEST_NETEM_APPROVED_NOT_SET
    exit 78
fi
if [[ "${DIST_TEST_NETEM_CLEANUP_APPROVED:-false}" != "true" ]]; then
    write_ledger ABORTED DIST_TEST_NETEM_CLEANUP_APPROVED_NOT_SET
    exit 78
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    write_ledger ABORTED LINUX_REQUIRED
    exit 78
fi
if [[ -z "$run_id" || ! "$run_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
    write_ledger ABORTED INVALID_RUN_ID
    exit 78
fi
if [[ -z "$interface" || ! "$interface" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    write_ledger ABORTED INVALID_INTERFACE
    exit 78
fi
if [[ -z "$target_node" || ! "$target_node" =~ ^node-[abc]$ ]]; then
    write_ledger ABORTED INVALID_TARGET_NODE
    exit 78
fi
if [[ ! "$delay" =~ ^[0-9]+(ms|s|us)$ || ! "$jitter" =~ ^[0-9]+(ms|s|us)$ ]]; then
    write_ledger ABORTED INVALID_DELAY
    exit 78
fi
if [[ -n "$loss" && ! "$loss" =~ ^[0-9]+(\.[0-9]+)?%$ ]]; then
    write_ledger ABORTED INVALID_LOSS
    exit 78
fi
if [[ -n "$reorder" && ! "$reorder" =~ ^[0-9]+(\.[0-9]+)?%$ ]]; then
    write_ledger ABORTED INVALID_REORDER
    exit 78
fi
if [[ -n "$netem_host" && -z "$netem_user" ]]; then
    write_ledger ABORTED NETEM_USER_REQUIRED
    exit 78
fi
if ! command -v tc >/dev/null 2>&1 && [[ -z "$netem_host" ]]; then
    write_ledger ABORTED TC_NOT_FOUND
    exit 78
fi

if [[ $# -eq 0 ]]; then
    write_ledger ABORTED COMMAND_REQUIRED
    exit 78
fi

cleanup() {
    local command_status=$?
    if tc_run tc qdisc del dev "$interface" root >/dev/null 2>&1; then
        if [[ $command_status -eq 0 ]]; then
            write_ledger CLEARED command_completed_qdisc_removed
        else
            write_ledger CLEARED command_failed_qdisc_removed
        fi
    else
        write_ledger ABORTED QDISC_CLEAR_FAILED
        return 78
    fi
    return "$command_status"
}
trap cleanup EXIT

write_ledger REQUESTED pending_apply
netem_args=(tc qdisc replace dev "$interface" root netem delay "$delay" "$jitter")
if [[ -n "$loss" ]]; then
    netem_args+=(loss "$loss")
fi
if [[ -n "$reorder" ]]; then
    netem_args+=(reorder "$reorder")
fi
if ! tc_run "${netem_args[@]}"; then
    write_ledger ABORTED QDISC_APPLY_FAILED
    exit 78
fi
write_ledger APPLIED qdisc_installed
"$@"
