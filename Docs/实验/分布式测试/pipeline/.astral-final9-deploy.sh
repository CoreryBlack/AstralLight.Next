#!/usr/bin/env bash
set -euo pipefail

RUN_ID=rust3n-dist-20260906-final9
DIST_DB_NAME=astral_f4rust_dist_test_20260906_final9
REDIS_PORT=16392
PORT_A=9205
PORT_B=9206
PORT_C=9207
BASE=/home/xg/astral-cs-final8-build-20260906
HARNESS=/home/xg/cs-harness-20260906-final8/Docs/实验/分布式测试/rust-s15
ROUTING_SOURCE=/home/xg/rust3n-dist-20260905-final5/run_config.json

source /home/xg/astral-cluster/credentials.env
source /home/xg/astral-cluster/endpoints.env
REDIS_PORT=16392
export MYSQL_ROOT="$DB_PASSWORD"
export RABBIT_USER="$RABBIT_USERNAME"
export RABBIT_PASS="$RABBIT_PASSWORD"
export MYSQL_HOST="${DB_HOST}:${DB_PORT}"

test -f "$ROUTING_SOURCE"
test "$(jq -r '.run_id' "$ROUTING_SOURCE")" = rust3n-dist-20260905-final5
test "$(sha256sum "$ROUTING_SOURCE" | cut -d' ' -f1)" = eedd1b0eb8600597a96a16c7461b8be74d4bf4a65e2a6cd55b125ceeb2a5fd4c
NODE_A_SSH=$(jq -r '.ssh["node-a"]' "$ROUTING_SOURCE")
NODE_C_SSH=$(jq -r '.ssh["node-c"]' "$ROUTING_SOURCE")
NODE_A_URL=$(jq -r '.nodes["node-a"]' "$ROUTING_SOURCE")
NODE_C_URL=$(jq -r '.nodes["node-c"]' "$ROUTING_SOURCE")
NODE_A_ADVERTISE_HOST=${NODE_A_URL#http://}
NODE_A_ADVERTISE_HOST=${NODE_A_ADVERTISE_HOST%%:*}
NODE_C_ADVERTISE_HOST=${NODE_C_URL#http://}
NODE_C_ADVERTISE_HOST=${NODE_C_ADVERTISE_HOST%%:*}

export RUN_ID DIST_DB_NAME REDIS_PORT PORT_A PORT_B PORT_C
export NODE_A_SSH NODE_C_SSH NODE_A_ADVERTISE_HOST NODE_C_ADVERTISE_HOST
export SNAP_BIN="$BASE/target/release/astral-trustgraph"
export BOOTSTRAP_BIN="$BASE/bootstrap-target/release/astral-e2e-bootstrap-final8"
export SOURCE_SNAPSHOT_SHA256=5886ebb4e2fe40c4fd71bd2cf3b04157fa8aac618b08b017402c1bbce049a81a
export SOURCE_GIT_REV=6822d38ba504c42f38411179cc7d79c3bea7c70f
export SOURCE_DIRTY_PATCH_SHA256=debf74998967774471eef12d5d3f25ca80de829eb6d627095d74c13c90bac771

test "$(sha256sum "$SNAP_BIN" | cut -d' ' -f1)" = 44d6b9562bb1b6022face27ec4313b80d270a3eb29c865f7f9b2dd94801fe6d0
test "$(sha256sum "$BOOTSTRAP_BIN" | cut -d' ' -f1)" = cccd7d1cfc65eb8255d754a93a33038105260e54ac92b8d989d7694ba188ef62

cd "$HARNESS"
exec bash ./deploy_dist.sh
