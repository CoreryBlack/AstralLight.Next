#!/usr/bin/env bash
set -euo pipefail

export PATH="/home/xg/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu

RUN_ID=rust3n-dist-20260906-final9
INTEGRATION_DB=astral_cs_integration_test_20260906_final9
RUN_BASE=/home/xg/$RUN_ID
BUILD=/home/xg/astral-cs-final8-build-20260906
HARNESS_ROOT=/home/xg/cs-harness-20260906-final8
EVIDENCE=/home/xg/astral-cs-evidence-20260906-final9
ROUTING_SOURCE=/home/xg/rust3n-dist-20260905-final5/run_config.json
OPA_CONTAINER=astral-evidence-opa-$RUN_ID
OPA_PORT=8193
OPA_IMAGE_ID=1a8ce152ab9a54353573e68bbbdf5c74f0f22d0eec3c9d90c2657a95d3281151
OPA_REPO_DIGEST=docker.m.daocloud.io/openpolicyagent/opa@sha256:cba27d3c6af2feba1e4d6e6b5e24df5b53db332420d4148a90acccd12efae6ed
RABBIT_VHOST=rust3n_dist_$RUN_ID
EXPECTED_HARNESS_SHA256=46baf0089238eeb99c3d82ec9282964c9c0f496fbe136217a984421791713cd5
EXPECTED_HARNESS_TAR_SHA256=246788e9fe540cca7b8697d00c59eba75ef206a8c66a768bd15954cbdc4500e3
EXPECTED_HARNESS_MANIFEST_SHA256=56758de8fc79cc9841fe64f84aed52ce5396b12c689c8c56464c1d970e158846
EXPECTED_TOCTOU_SHA256=5db49fa737fb2a0974948d3eee4a998d397afb77838dffe6bcf3f5aa2eaa6ac1
EXPECTED_INTEGRATION_TREE_SHA256=65b86eae3728bc0544cfa5bd8981c353e0e31842d267adf93cad951245488bb7
EXPECTED_ROUTING_SOURCE_SHA256=eedd1b0eb8600597a96a16c7461b8be74d4bf4a65e2a6cd55b125ceeb2a5fd4c
EXPECTED_ROUTING_SOURCE_RUN_ID=rust3n-dist-20260905-final5
HARNESS_DIR="$HARNESS_ROOT/Docs/实验/分布式测试/rust-s15"
HARNESS_TAR="$HARNESS_ROOT/.astral-final8-harness.tar.gz"
HARNESS_MANIFEST="$HARNESS_ROOT/.astral-final8-harness-manifest.sha256"
TOCTOU_RACE="$HARNESS_ROOT/AstralLight-Rust/bench/loadgen/scripts/toctou_race.py"
INTEGRATION_ROOT="$BUILD/src/AstralLight-Rust"

source /home/xg/astral-cluster/credentials.env
source /home/xg/astral-cluster/endpoints.env
RUN_ID=rust3n-dist-20260906-final9
INTEGRATION_DB=astral_cs_integration_test_20260906_final9
OPA_CONTAINER=astral-evidence-opa-$RUN_ID
OPA_PORT=8193
RABBIT_VHOST=rust3n_dist_$RUN_ID

# Fresh-only ownership checks. A partial prior attempt must be reconciled first.
test -d "$RUN_BASE"
test -d "$HARNESS_DIR"
test ! -e "$EVIDENCE"
test -f "$ROUTING_SOURCE"
test -f "$HARNESS_TAR"
test -f "$HARNESS_MANIFEST"
test -f "$TOCTOU_RACE"
test -d "$INTEGRATION_ROOT"

routing_source_run_id=$(jq -r '.run_id' "$ROUTING_SOURCE")
routing_source_sha256=$(sha256sum "$ROUTING_SOURCE" | cut -d' ' -f1)
test "$routing_source_run_id" = "$EXPECTED_ROUTING_SOURCE_RUN_ID"
test "$routing_source_sha256" = "$EXPECTED_ROUTING_SOURCE_SHA256"

test "$(sha256sum "$HARNESS_TAR" | cut -d' ' -f1)" = "$EXPECTED_HARNESS_TAR_SHA256"
test "$(sha256sum "$HARNESS_MANIFEST" | cut -d' ' -f1)" = "$EXPECTED_HARNESS_MANIFEST_SHA256"
manifest_count=$(wc -l < "$HARNESS_MANIFEST")
test "$manifest_count" -eq 10
(
  cd "$HARNESS_DIR"
  sha256sum -c "$HARNESS_MANIFEST" >/dev/null
)
harness_archive_count=$(tar -tzf "$HARNESS_TAR" | grep -cv '/$')
test "$harness_archive_count" -eq 10
harness_combined_sha256=$(python3 - "$HARNESS_DIR" <<'PY'
import hashlib, os, sys
root=sys.argv[1]
names=("deploy_dist.sh","e2e-bootstrap-v2-main.rs","f7_recheck.py","rq345_20260903.py","rq_fill_20260901.py","run_cs_evidence.py","s15_coordinator.py","s15_perf.py","seed_f4rust.sql","README.md")
h=hashlib.sha256()
for name in names:
    d=hashlib.sha256(open(os.path.join(root,name),'rb').read()).hexdigest()
    h.update(name.encode()); h.update(b'\0'); h.update(d.encode()); h.update(b'\n')
print(h.hexdigest())
PY
)
test "$harness_combined_sha256" = "$EXPECTED_HARNESS_SHA256"
toctou_sha256=$(sha256sum "$TOCTOU_RACE" | cut -d' ' -f1)
test "$toctou_sha256" = "$EXPECTED_TOCTOU_SHA256"
read -r integration_tree_sha256 integration_tree_files < <(python3 - "$INTEGRATION_ROOT" <<'PY'
import hashlib, os, sys
root=sys.argv[1]
entries=[]
for base, dirs, files in os.walk(root, followlinks=False):
    dirs.sort(); files.sort()
    if any(os.path.islink(os.path.join(base, name)) for name in dirs): raise SystemExit(2)
    for name in files:
        path=os.path.join(base,name)
        if os.path.islink(path) or not os.path.isfile(path): raise SystemExit(2)
        rel=os.path.relpath(path,root).replace(os.sep,'/')
        entries.append((rel,hashlib.sha256(open(path,'rb').read()).hexdigest()))
h=hashlib.sha256()
for rel,digest in sorted(entries):
    h.update(rel.encode()); h.update(b'\0'); h.update(digest.encode()); h.update(b'\n')
print(h.hexdigest(),len(entries))
PY
)
test "$integration_tree_sha256" = "$EXPECTED_INTEGRATION_TREE_SHA256"
test "$integration_tree_files" -eq 382
if docker ps -a --format '{{.Names}}' | grep -Fxq "$OPA_CONTAINER"; then
  printf 'OPA container already exists: %s\n' "$OPA_CONTAINER" >&2
  exit 1
fi
if ss -H -ltn "sport = :$OPA_PORT" | grep -q .; then
  printf 'OPA port occupied: %s\n' "$OPA_PORT" >&2
  exit 1
fi
actual_image_id=$(docker image inspect openpolicyagent/opa:latest --format '{{.Id}}')
test "$actual_image_id" = "sha256:$OPA_IMAGE_ID"
actual_repo_digest=$(docker image inspect openpolicyagent/opa:latest --format '{{index .RepoDigests 0}}')
test "$actual_repo_digest" = "$OPA_REPO_DIGEST"

tmp_cnf=$(docker exec astral_bench_mysql sh -c 'umask 077; mktemp /tmp/.final9_setup_cnf_XXXXXXXX')
tmp_user_cnf=$(docker exec astral_bench_mysql sh -c 'umask 077; mktemp /tmp/.final9_user_cnf_XXXXXXXX')
schema_remote=""
cleanup() {
  test -z "${tmp_cnf:-}" || docker exec astral_bench_mysql rm -f "$tmp_cnf" >/dev/null 2>&1 || true
  test -z "${tmp_user_cnf:-}" || docker exec astral_bench_mysql rm -f "$tmp_user_cnf" >/dev/null 2>&1 || true
  test -z "${schema_remote:-}" || docker exec astral_bench_mysql rm -f "$schema_remote" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP
printf '[client]\nuser=root\npassword="%s"\n' "$DB_PASSWORD" \
  | docker exec -i astral_bench_mysql sh -c "cat > '$tmp_cnf' && chmod 600 '$tmp_cnf'"
printf '[client]\nhost=%s\nport=%s\nuser=%s\npassword="%s"\nprotocol=tcp\n' \
  "$DB_HOST" "$DB_PORT" "$DB_USER" "$DB_PASSWORD" \
  | docker exec -i astral_bench_mysql sh -c "cat > '$tmp_user_cnf' && chmod 600 '$tmp_user_cnf'"
MYSQL="mysql --defaults-extra-file=$tmp_cnf"
MYSQLDUMP="mysqldump --defaults-extra-file=$tmp_cnf"
exists=$(docker exec astral_bench_mysql sh -c "exec $MYSQL -uroot -N -e 'SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=\"$INTEGRATION_DB\"'")
test "$exists" = 0
schema_remote=$(docker exec astral_bench_mysql sh -c 'umask 077; mktemp /tmp/.final9_integration_schema_XXXXXXXX.sql')
docker exec astral_bench_mysql sh -c "exec $MYSQLDUMP -uroot --no-data --single-transaction --skip-lock-tables --no-tablespaces astral_test > '$schema_remote'"
docker exec astral_bench_mysql sh -c "exec $MYSQLDUMP -uroot --no-create-info --skip-lock-tables --no-tablespaces astral_test _sqlx_migrations >> '$schema_remote'"
integration_schema_dump_sha256=$(docker exec astral_bench_mysql sha256sum "$schema_remote" | cut -d' ' -f1)
docker exec astral_bench_mysql sh -c "exec $MYSQL -uroot -e 'CREATE DATABASE $INTEGRATION_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci'"
docker exec astral_bench_mysql sh -c "exec $MYSQL -uroot $INTEGRATION_DB < '$schema_remote'"
integration_tables=$(docker exec astral_bench_mysql sh -c "exec $MYSQL -uroot -N -e 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\"$INTEGRATION_DB\"'")
integration_migrations=$(docker exec astral_bench_mysql sh -c "exec $MYSQL -uroot -N -e 'SELECT COUNT(*) FROM $INTEGRATION_DB._sqlx_migrations'")
test "$integration_tables" = 122
test "$integration_migrations" = 46
probe_value=$(docker exec astral_bench_mysql sh -c "exec mysql --defaults-extra-file='$tmp_user_cnf' -N '$INTEGRATION_DB' -e 'CREATE TABLE final9_user_write_probe (probe_id BIGINT NOT NULL PRIMARY KEY); INSERT INTO final9_user_write_probe VALUES (1); SELECT COUNT(*) FROM final9_user_write_probe; DROP TABLE final9_user_write_probe'")
test "$probe_value" = 1
integration_user_write_probe=true
docker exec astral_bench_mysql rm -f "$schema_remote"
schema_remote=""

docker run -d --name "$OPA_CONTAINER" -p "127.0.0.1:$OPA_PORT:8181" \
  "$actual_image_id" run --server --addr :8181 --log-level error >/dev/null
for _ in $(seq 1 30); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$OPA_PORT/health" || true)
  test "$code" = 200 && break
  sleep 1
done
test "${code:-}" = 200
opa_version=$(docker exec "$OPA_CONTAINER" /opa version \
  | sed -n 's/^Version:[[:space:]]*//p' | head -n 1)
test -n "$opa_version"

test "$RABBIT_VHOST" != rust3n_dist
vhosts=$(docker exec astral_bench_rabbitmq rabbitmqctl -q list_vhosts name)
printf '%s\n' "$vhosts" | grep -Fxq "$RABBIT_VHOST"
rabbit_connections=0
rabbit_audit_consumers=0
rabbit_dlx_consumers=0
for _ in $(seq 1 120); do
  rabbit_connections=$(docker exec astral_bench_rabbitmq rabbitmqctl -q list_connections vhost \
    | grep -Fxc "$RABBIT_VHOST" || true)
  rabbit_audit_consumers=$(docker exec astral_bench_rabbitmq rabbitmqctl -q list_queues -p "$RABBIT_VHOST" name consumers \
    | awk '$1=="astral.audit.log" {print $2}')
  rabbit_dlx_consumers=$(docker exec astral_bench_rabbitmq rabbitmqctl -q list_queues -p "$RABBIT_VHOST" name consumers \
    | awk '$1=="astral.dlx.audit.log" {print $2}')
  if [ "$rabbit_connections" -ge 3 ] \
      && [ "${rabbit_audit_consumers:-0}" = 3 ] \
      && [ "${rabbit_dlx_consumers:-0}" = 3 ]; then
    break
  fi
  sleep 1
done
test "$rabbit_connections" -ge 3
test "${rabbit_audit_consumers:-0}" = 3
test "${rabbit_dlx_consumers:-0}" = 3

trustgraph_sha256=$(sha256sum "$BUILD/target/release/astral-trustgraph" | cut -d' ' -f1)
engine_sha256=$(sha256sum "$BUILD/ec-target/release/engine-comparison" | cut -d' ' -f1)
bootstrap_sha256=$(sha256sum "$BUILD/bootstrap-target/release/astral-e2e-bootstrap-final8" | cut -d' ' -f1)
source_tar_sha256=$(sha256sum "$BUILD/input/.astral-final8-source.tar.gz" | cut -d' ' -f1)
source_manifest_sha256=$(sha256sum "$BUILD/input/.astral-final8-source-manifest.sha256" | cut -d' ' -f1)
test "$source_manifest_sha256" = 5886ebb4e2fe40c4fd71bd2cf3b04157fa8aac618b08b017402c1bbce049a81a
dirty_patch_sha256=$(sha256sum "$BUILD/input/.astral-final8-dirty.patch" | cut -d' ' -f1)
routing_source_sha256=$(sha256sum "$ROUTING_SOURCE" | cut -d' ' -f1)
harness_tar_sha256=$(sha256sum "$HARNESS_TAR" | cut -d' ' -f1)
harness_manifest_file_sha256=$(sha256sum "$HARNESS_MANIFEST" | cut -d' ' -f1)
source_git_rev=6822d38ba504c42f38411179cc7d79c3bea7c70f
rustc_version=$(rustc --version | awk '{print $2}')
cargo_version=$(cargo --version | awk '{print $2}')
docker_version=$(docker version --format '{{.Client.Version}}')
mysql_version=$(docker exec astral_bench_mysql mysql --version \
  | awk '{for (i=1; i<=NF; i++) if ($i=="Ver") {print $(i+1); exit}}')
test -n "$rustc_version"
test -n "$cargo_version"
test -n "$docker_version"
test -n "$mysql_version"
mkdir -p "$EVIDENCE"
export RUN_ID source_tar_sha256 source_manifest_sha256 dirty_patch_sha256 source_git_rev
export trustgraph_sha256 engine_sha256 bootstrap_sha256 harness_tar_sha256
export harness_manifest_file_sha256 harness_combined_sha256 routing_source_sha256
export routing_source_run_id toctou_sha256 integration_tree_sha256 integration_tree_files
export integration_user_write_probe
export INTEGRATION_DB integration_schema_dump_sha256 integration_tables integration_migrations
export OPA_CONTAINER OPA_PORT OPA_IMAGE_ID OPA_REPO_DIGEST opa_version
export RABBIT_VHOST rabbit_connections rabbit_audit_consumers rabbit_dlx_consumers
export rustc_version cargo_version docker_version mysql_version
python3 - "$EVIDENCE/setup_provenance.json" <<'PY'
import datetime, json, os, sys
obj={
 "run_id":os.environ["RUN_ID"],"created_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "source_tar_sha256":os.environ["source_tar_sha256"],"source_manifest_sha256":os.environ["source_manifest_sha256"],
 "dirty_patch_sha256":os.environ["dirty_patch_sha256"],"source_git_rev":os.environ["source_git_rev"],
 "trustgraph_sha256":os.environ["trustgraph_sha256"],"engine_sha256":os.environ["engine_sha256"],
 "bootstrap_sha256":os.environ["bootstrap_sha256"],"harness_tar_sha256":os.environ["harness_tar_sha256"],
 "harness_manifest_file_sha256":os.environ["harness_manifest_file_sha256"],
 "harness_combined_sha256":os.environ["harness_combined_sha256"],
 "routing_source_sha256":os.environ["routing_source_sha256"],
 "routing_source_run_id":os.environ["routing_source_run_id"],
 "toctou_sha256":os.environ["toctou_sha256"],
 "integration_tree_sha256":os.environ["integration_tree_sha256"],
 "integration_tree_files":int(os.environ["integration_tree_files"]),
 "integration_user_write_probe":os.environ["integration_user_write_probe"]=="true",
 "integration_db":os.environ["INTEGRATION_DB"],
 "integration_schema_dump_sha256":os.environ["integration_schema_dump_sha256"],
 "integration_tables":int(os.environ["integration_tables"]),"integration_migrations":int(os.environ["integration_migrations"]),
 "opa_container":os.environ["OPA_CONTAINER"],"opa_port":int(os.environ["OPA_PORT"]),
 "opa_image_id":os.environ["OPA_IMAGE_ID"],"opa_repo_digest":os.environ["OPA_REPO_DIGEST"],
 "opa_version":os.environ["opa_version"],"rabbit_vhost":os.environ["RABBIT_VHOST"],
 "rabbit_connections":int(os.environ["rabbit_connections"]),
 "rabbit_audit_consumers":int(os.environ["rabbit_audit_consumers"]),
 "rabbit_dlx_consumers":int(os.environ["rabbit_dlx_consumers"]),
 "redis_container":"astral_dist_redis_"+os.environ["RUN_ID"],"redis_port":16392,
 "node_ports":{"node-a":9205,"node-b":9206,"node-c":9207},
 "rustc_version":os.environ["rustc_version"],"cargo_version":os.environ["cargo_version"],
 "docker_version":os.environ["docker_version"],"mysql_version":os.environ["mysql_version"],
}
with open(sys.argv[1],"x",encoding="utf-8") as f: json.dump(obj,f,indent=1,sort_keys=True)
os.chmod(sys.argv[1],0o644)
PY
printf 'SETUP_PASS run_id=%s integration_tables=%s migrations=%s rabbit_connections=%s\n' \
  "$RUN_ID" "$integration_tables" "$integration_migrations" "$rabbit_connections"
