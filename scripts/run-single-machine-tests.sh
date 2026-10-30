#!/usr/bin/env bash
# AstralLight 单机测试一键入口（single-machine test driver）。
#
# 职责边界（遵循 AGENTS.md §5/§10.0 与 tests-suite/README.md）：
# - 本脚本只负责：探测工具链、按 MANIFEST profile 派发 Rust `test-campaign`
#   runner、启动未登记为 suite 的本地 CPU/release 探针、收集原始日志与退出码。
# - suite 选择、服务前置校验、性能验收与 PASS/FAIL/SKIP/BLOCKED/UNKNOWN 判定
#   全部由 Rust runner 与 Cargo/libtest 完成；本脚本不承载测试逻辑或判定。
# - 本脚本不创建数据库、不执行迁移、不启动服务或容器；真实依赖资源准备
#   是独立的批准动作，runner 会做严格前置校验（loopback:3308 run-scoped 库等）。
#
# 用法：
#   scripts/run-single-machine-tests.sh                  # 默认三 profile 集合 + 本地探针
#   scripts/run-single-machine-tests.sh --list-only      # 只输出 runner 注册清单
#   scripts/run-single-machine-tests.sh --verify-items   # 集合运行前先逐项预验证
#   scripts/run-single-machine-tests.sh --with-mysql     # 追加 native-single-node 真实 MySQL 集
#   scripts/run-single-machine-tests.sh --with-rabbit    # 追加 standalone-rabbit 集（含 MySQL 前置）
#   scripts/run-single-machine-tests.sh --skip-probes    # 跳过未登记的本地探针
#   scripts/run-single-machine-tests.sh --log-dir DIR    # 自定义日志目录
#
# 默认集合（无外部服务）= native-kernel + offline-validation + performance-kernel：
# workspace 非 ignored 测试、本地契约/安全边界、E2 五项 omission、test-harness
# 离线合约与有界模型（含 E5 release 全枚举）、criterion/divan bench、
# policy-evaluate-benefit 与 82/15/40-case 性能矩阵。完整首跑可能 30-90 分钟。
#
# 真实依赖前置（--with-mysql / --with-rabbit；脚本只查变量存在性，语义由 runner 校验）：
#   TEST_USE_EXISTING=1
#   ASTRAL_MIGRATION_ENV=isolated
#   RUST_INTEGRATION_REQUIRED=1
#   DATABASE_URL=mysql://...@127.0.0.1:3308/astral_rehearsal_<run-suffix>
#   ASTRAL_TEST_DATABASE_NAME=astral_rehearsal_<同一后缀>
#   INTEGRATION_IDENTITY_MAPPING_DATABASE_URL=mysql://...@127.0.0.1:3308/sdk_identity_mapping_test_*
#   INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE=<同名>
#   --with-rabbit 另需：RABBITMQ_URL=amqp://user:pass@127.0.0.1:5673/<显式vhost>
#
# 明确不在本脚本范围（另行处理）：
#   S15/三节点 live distributed campaign、performance-native 签名 HTTP campaign
#   （需批准部署）、外部 comparator 实测（Casbin/OPA/Cedar/SpiceDB）、
#   Redis/COMPAT 历史面、MT-E2（未实现）、iai/Valgrind（Linux 专用）、
#   Learn/Chat/integrations（workspace 之外的冻结/独立 crate）。

set -uo pipefail

usage() {
    sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

LIST_ONLY=0
VERIFY_ITEMS=0
WITH_MYSQL=0
WITH_RABBIT=0
SKIP_PROBES=0
LOG_DIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --list-only) LIST_ONLY=1 ;;
        --verify-items) VERIFY_ITEMS=1 ;;
        --with-mysql) WITH_MYSQL=1 ;;
        --with-rabbit) WITH_RABBIT=1 ;;
        --skip-probes) SKIP_PROBES=1 ;;
        --log-dir)
            [ "$#" -ge 2 ] || { printf -- '--log-dir 需要一个目录参数\n' >&2; exit 2; }
            LOG_DIR="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf '未知选项: %s（-h 查看用法）\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

command -v cargo >/dev/null 2>&1 || { printf '未找到 cargo，请先安装 Rust 工具链\n' >&2; exit 2; }

RUN_ID="single-machine-$(date +%Y%m%d-%H%M%S)-$$"
LOG_DIR="${LOG_DIR:-$ROOT/target/test-runs/$RUN_ID}"
mkdir -p "$LOG_DIR" || exit 2

RESULTS=()

run_phase() {
    local name="$1"; shift
    local log="$LOG_DIR/$name.log"
    printf '\n=== [%s] 开始  %s\n    log: %s\n' "$(date '+%H:%M:%S')" "$name" "$log"
    ( "$@" ) >"$log" 2>&1
    local rc=$?
    RESULTS+=("$name|$rc|$log")
    printf '=== [%s] 结束  exit=%d\n' "$name" "$rc"
    return 0
}

require_env() {
    local missing=""
    for var in "$@"; do
        [ -n "${!var:-}" ] || missing="$missing $var"
    done
    if [ -n "$missing" ]; then
        printf '[MISSING-ENV] 缺少前置环境变量:%s\n（脚本不会代为创建资源；请准备好隔离库/服务后重试该 phase）\n' "$missing" >&2
        return 1
    fi
    return 0
}

RUNNER=(bash scripts/run-tests.sh --campaign)

# Phase 1：注册清单（始终执行，作为本轮证据基线）
run_phase 10-inventory "${RUNNER[@]}" --list --json

if [ "$LIST_ONLY" -eq 1 ]; then
    printf '\n清单已写入 %s/10-inventory.log\n' "$LOG_DIR"
    exit 0
fi

# Phase 2：默认无外部服务集合（native-kernel + offline-validation + performance-kernel）
VERIFY_ARGS=()
[ "$VERIFY_ITEMS" -eq 1 ] && VERIFY_ARGS=(--verify-items)
run_phase 20-default-campaign "${RUNNER[@]}" --run \
    --profile native-kernel --profile offline-validation --profile performance-kernel \
    ${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}

# Phase 3：未登记为 MANIFEST suite 的本地探针（直接 Cargo，仅收集原始日志；
# 不经过 runner 验收，不作为 PERF_MATRIX 类性能证据）。
if [ "$SKIP_PROBES" -eq 0 ]; then
    PROBE_SPECS=(
        "debug|astral-db|memory_projection_hub::tests::assembly_cache::assembly_cache_performance_probe|assembly_cache_probe"
        "debug|astral-db|memory_projection_hub::tests::memory_evidence_read_throughput_and_tail_latency_under_warm_multi_card_mirror|mirror_read_throughput_probe"
        "debug|astral-trustgraph|service::authorization_projector::planning::parent_ordinals::tests::stage_planning_lookup_performance_probe|stage_planning_lookup_probe"
        "debug|astral-trustgraph|service::authorization_projector::tests::performance::segment_digest_hint_scheduling_curve|digest_hint_scheduling_curve"
        "debug|astral-trustgraph|service::local_projection_worker::tests::shared_ledger_performance_probe|shared_ledger_probe"
        "debug|astral-mq|local_bus::tests::limit_sustained_delivery_throughput|local_bus_throughput_probe"
        "release|astral-db|memory_projection_hub::tests::supply_chain_ceiling_probe|supply_chain_ceiling_probe"
        "release|astral-trustgraph|service::authorization_projector::tests::performance::segment_digest_hint_capacity_pressure_curve|digest_hint_capacity_curve"
        "release|policy-engine|engine::ceiling_probe::authorization_ceiling_probe|authorization_ceiling_probe"
        "release|policy-engine|engine::published::matcher_curve::matcher_cache_candidate_strategy_curve|matcher_candidate_strategy_curve"
        "release|policy-engine|engine::published::matcher_curve::matcher_cost_position_curve|matcher_cost_position_curve"
        "release|astral-common|task_scheduling_probe::foreground_relay_curve_sweep|foreground_relay_curve_sweep"
    )
    for spec in "${PROBE_SPECS[@]}"; do
        IFS='|' read -r probe_mode probe_crate probe_path probe_name <<<"$spec"
        if [ "$probe_mode" = "release" ]; then
            probe_args=(cargo test --release -p "$probe_crate" --lib "$probe_path" --locked \
                -- --exact --ignored --nocapture --test-threads=1)
        else
            probe_args=(cargo test -p "$probe_crate" --lib "$probe_path" --locked \
                -- --exact --ignored --nocapture --test-threads=1)
        fi
        run_phase "3x-probe-$probe_name" "${probe_args[@]}"
    done
fi

# Phase 4（可选）：native-single-node 真实 MySQL 集合
if [ "$WITH_MYSQL" -eq 1 ]; then
    if require_env TEST_USE_EXISTING ASTRAL_MIGRATION_ENV RUST_INTEGRATION_REQUIRED \
        DATABASE_URL ASTRAL_TEST_DATABASE_NAME \
        INTEGRATION_IDENTITY_MAPPING_DATABASE_URL INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE
    then
        run_phase 40-mysql-native-single-node "${RUNNER[@]}" --run --profile native-single-node
    else
        RESULTS+=("40-mysql-native-single-node|2|missing-env")
    fi
fi

# Phase 5（可选）：standalone-rabbit 集合（MySQL + RabbitMQ）
if [ "$WITH_RABBIT" -eq 1 ]; then
    if require_env TEST_USE_EXISTING ASTRAL_MIGRATION_ENV RUST_INTEGRATION_REQUIRED \
        DATABASE_URL ASTRAL_TEST_DATABASE_NAME \
        INTEGRATION_IDENTITY_MAPPING_DATABASE_URL INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE \
        RABBITMQ_URL
    then
        run_phase 50-rabbit-standalone "${RUNNER[@]}" --run --profile standalone-rabbit
    else
        RESULTS+=("50-rabbit-standalone|2|missing-env")
    fi
fi

printf '\n===== 单机测试汇总（runId=%s）=====\n' "$RUN_ID"
worst=0
for result in "${RESULTS[@]}"; do
    IFS='|' read -r phase_name phase_rc phase_log <<<"$result"
    printf '%-46s exit=%-3s log=%s\n' "$phase_name" "$phase_rc" "$phase_log"
    [ "$phase_rc" -gt "$worst" ] && worst=$phase_rc
done

cat <<'EOF'

范围说明：
- 已执行 phase 的 PASS/FAIL/SKIP/BLOCKED/UNKNOWN 语义以 runner 与 Cargo 输出为准，
  本汇总仅报告退出码；exit 0 不等于业务 PASS（ignored/[SKIP] 在日志中单独计数）。
- 未包含（需另行处理）：S15/三节点 live distributed campaign、performance-native
  签名 HTTP campaign、外部 comparator 实测、Redis/COMPAT 历史面、MT-E2、
  iai/Valgrind（Linux）、Learn/Chat/integrations、需 MySQL+Rabbit 的未登记 lib 骨架测试。
EOF

exit "$worst"
