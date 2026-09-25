#!/bin/bash
# =============================================================================
# AstralLight 全量测试总入口
# 依次调用: 单元/集成测试 → Benchmark
# 用法:
#   bash scripts/run-all-tests.sh                         # 跑全部
#   bash scripts/run-all-tests.sh --skip-benchmark        # 仅单元/集成测试
#   bash scripts/run-all-tests.sh --only-benchmark        # 仅 Benchmark
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKIP_BENCHMARK=false
ONLY_BENCHMARK=false

for arg in "$@"; do
    case "$arg" in
        --skip-benchmark) SKIP_BENCHMARK=true ;;
        --only-benchmark) ONLY_BENCHMARK=true ;;
    esac
done

if [ "$ONLY_BENCHMARK" = false ]; then
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     GROUP 1: Unit & Integration Tests                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    bash "$SCRIPT_DIR/run-unit-integration-tests.sh"
fi

if [ "$SKIP_BENCHMARK" = false ]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     GROUP 2: Benchmark + 5-System Comparison             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    bash "$SCRIPT_DIR/run-benchmark.sh"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              ALL TEST GROUPS COMPLETE                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
