#!/usr/bin/env bash
set -euo pipefail

RUN_ID=rust3n-dist-20260906-final9
BUILD=/home/xg/astral-cs-final8-build-20260906
HARNESS=/home/xg/cs-harness-20260906-final8/Docs/实验/分布式测试/rust-s15
EVIDENCE=/home/xg/astral-cs-evidence-20260906-final9
INTEGRATION_DB=astral_cs_integration_test_20260906_final9
OPA_CONTAINER=astral-evidence-opa-$RUN_ID

export PATH="/home/xg/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu
source /home/xg/astral-cluster/credentials.env
source /home/xg/astral-cluster/endpoints.env
RUN_ID=rust3n-dist-20260906-final9
INTEGRATION_DB=astral_cs_integration_test_20260906_final9
OPA_CONTAINER=astral-evidence-opa-$RUN_ID
export RUST_INTEGRATION_REQUIRED=1
export CARGO_TARGET_DIR="$BUILD/integration-target-final9"
export DATABASE_URL="mysql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${INTEGRATION_DB}"
unset DB_PASSWORD RABBIT_PASSWORD RABBIT_USERNAME REDIS_PASSWORD DB_HOST DB_PORT DB_USER DB_NAME RABBIT_HOST RABBIT_PORT REDIS_HOST REDIS_PORT

cd "$HARNESS"
set +e
python3 -u run_cs_evidence.py \
  --run-config "/home/xg/$RUN_ID/run_config.json" \
  --setup-provenance "$EVIDENCE/setup_provenance.json" \
  --expected-run-id "$RUN_ID" \
  --expected-binary-sha256 44d6b9562bb1b6022face27ec4313b80d270a3eb29c865f7f9b2dd94801fe6d0 \
  --expected-source-sha256 5886ebb4e2fe40c4fd71bd2cf3b04157fa8aac618b08b017402c1bbce049a81a \
  --expected-source-tar-sha256 0eccc0131b2c116ad78d98f0c2cf028494b9b2cc87a00e33965fe42e2d07d74e \
  --expected-source-git-rev 6822d38ba504c42f38411179cc7d79c3bea7c70f \
  --expected-dirty-patch-sha256 debf74998967774471eef12d5d3f25ca80de829eb6d627095d74c13c90bac771 \
  --expected-bootstrap-sha256 cccd7d1cfc65eb8255d754a93a33038105260e54ac92b8d989d7694ba188ef62 \
  --expected-engine-sha256 4e7ae52caed48f20c9cc6e6e50371f172c6ab7377e82dbca19aaef25b99d8cfa \
  --expected-harness-sha256 46baf0089238eeb99c3d82ec9282964c9c0f496fbe136217a984421791713cd5 \
  --expected-routing-source-sha256 eedd1b0eb8600597a96a16c7461b8be74d4bf4a65e2a6cd55b125ceeb2a5fd4c \
  --expected-routing-source-run-id rust3n-dist-20260905-final5 \
  --expected-toctou-sha256 5db49fa737fb2a0974948d3eee4a998d397afb77838dffe6bcf3f5aa2eaa6ac1 \
  --expected-integration-tree-sha256 65b86eae3728bc0544cfa5bd8981c353e0e31842d267adf93cad951245488bb7 \
  --expected-integration-db "$INTEGRATION_DB" \
  --expected-opa-image-id 1a8ce152ab9a54353573e68bbbdf5c74f0f22d0eec3c9d90c2657a95d3281151 \
  --expected-opa-repo-digest docker.m.daocloud.io/openpolicyagent/opa@sha256:cba27d3c6af2feba1e4d6e6b5e24df5b53db332420d4148a90acccd12efae6ed \
  --out-dir "$EVIDENCE" \
  --rounds 3 \
  --ec-bin "$BUILD/ec-target/release/engine-comparison" \
  --ec-cwd "$BUILD/src/AstralLight-Rust/bench/engine-comparison" \
  --ec-repeats 5 \
  --ec-opa http://127.0.0.1:8193 \
  --integration-cwd "$BUILD/src/AstralLight-Rust" \
  --integration-cmd "[\"cargo\",\"test\",\"--manifest-path\",\"$BUILD/src/AstralLight-Rust/Cargo.toml\",\"--locked\",\"-p\",\"astral-db\",\"--test\",\"authorization_projection_integration\",\"--release\",\"--\",\"--ignored\",\"--test-threads=1\"]" \
  --integration-env DATABASE_URL,RUST_INTEGRATION_REQUIRED,CARGO_TARGET_DIR,RUSTUP_TOOLCHAIN
campaign_rc=$?
set -e

opa_removed=false
if docker ps -a --format '{{.Names}}' | grep -Fxq "$OPA_CONTAINER"; then
  docker rm -f "$OPA_CONTAINER" >/dev/null
  opa_removed=true
fi
export campaign_rc opa_removed RUN_ID
python3 - "$EVIDENCE/teardown.json" <<'PY'
import datetime,json,os,sys
with open(sys.argv[1],"x",encoding="utf-8") as f:
 json.dump({"run_id":os.environ["RUN_ID"],"campaign_exit_code":int(os.environ["campaign_rc"]),"opa_removed":os.environ["opa_removed"]=="true","finished_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()},f,indent=1)
PY
exit "$campaign_rc"
