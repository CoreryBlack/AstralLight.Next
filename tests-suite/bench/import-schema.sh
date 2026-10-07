#!/bin/bash
# ── schema 导入辅助脚本 ──
# 用法：由 comparison-5x-run.sh 在宿主机上执行
# 依赖：python3, docker, MySQL 容器 astral_bench_mysql
set -euo pipefail

: "${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
BENCHMARK_MYSQL_CONTAINER="${BENCHMARK_MYSQL_CONTAINER:-astral_bench_mysql}"

SCHEMA_SOURCE="${1:?Usage: $0 <schema.sql> [database_name]}"
DB_NAME="${2:-astrallight}"
TMP_LOCAL="/tmp/schema_import_${DB_NAME}.sql"
TMP_REMOTE="/tmp/schema_import.sql"

echo "  Replacing 'platform_v4' -> '${DB_NAME}' in schema..."
python3 -c "
import sys
src, dst, db = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src) as f:
    sql = f.read().replace('platform_v4', db)
with open(dst, 'w') as f:
    f.write(sql)
print(f'  Written {len(sql)} bytes to {dst}')
" "$SCHEMA_SOURCE" "$TMP_LOCAL" "$DB_NAME"

echo "  Copying to MySQL container..."
docker cp "$TMP_LOCAL" "${BENCHMARK_MYSQL_CONTAINER}:${TMP_REMOTE}"

echo "  Importing into ${DB_NAME}..."
# 使用 -e "source file" 代替 < 重定向，避免外层 shell 解释
docker exec "${BENCHMARK_MYSQL_CONTAINER}" mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" "$DB_NAME" -e "source ${TMP_REMOTE}" 2>&1 | tail -5

sleep 2
TABLES=$(docker exec "${BENCHMARK_MYSQL_CONTAINER}" mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" -sN "$DB_NAME" -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'" 2>/dev/null | grep -v Warning || echo "0")
echo "  Schema imported: ${TABLES} tables"

rm -f "$TMP_LOCAL"
exit 0
