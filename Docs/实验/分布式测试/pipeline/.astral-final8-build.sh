#!/usr/bin/env bash
# final8 build: runs ON node-b. Extracts the frozen source tar + harness tar
# into one clean tree, builds the three release binaries, records identities.
set -euo pipefail

BASE=/home/xg/astral-cs-final8-build-20260906
STAGING=/home/xg/.astral-final8-staging
INPUT="$BASE/input"
SRC="$BASE/src"
CARGO=/home/xg/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo
export PATH=/home/xg/.cargo/bin:$PATH
export RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu
export CARGO_HOME=/home/xg/.cargo
export RUSTUP_HOME=/home/xg/.rustup

EXPECTED_SOURCE_COUNT=4200
EXPECTED_HARNESS_COUNT=10
EXPECTED_SOURCE_TAR_SHA256=0eccc0131b2c116ad78d98f0c2cf028494b9b2cc87a00e33965fe42e2d07d74e
EXPECTED_SOURCE_MANIFEST_SHA256=5886ebb4e2fe40c4fd71bd2cf3b04157fa8aac618b08b017402c1bbce049a81a
EXPECTED_DIRTY_PATCH_SHA256=debf74998967774471eef12d5d3f25ca80de829eb6d627095d74c13c90bac771
EXPECTED_HARNESS_TAR_SHA256=5b0c67b8e99ee0205f53958f40997a7fd4702bfd2cdd8498dbcfc38992a269b2
EXPECTED_HARNESS_MANIFEST_SHA256=b408656787cdc3115c5fc3eca28ec704ef54415c38bc0b36dacc10780eb52719

# Fresh-only build directory. Inputs arrive via staging (uploaded before the
# build base exists) and move into $BASE/input after the ownership check.
if [ -e "$BASE" ]; then
  echo "build base already exists: $BASE (reconcile before retry)"; exit 1
fi
for f in .astral-final8-source.tar.gz .astral-final8-source-manifest.sha256 \
         .astral-final8-dirty.patch .astral-final8-harness.tar.gz \
         .astral-final8-harness-manifest.sha256 .astral-final8-build.sh; do
  test -f "$STAGING/$f" || { echo "staging input missing: $f"; exit 1; }
done
mkdir -p "$BASE" "$INPUT"
mv "$STAGING"/.astral-final8-*.tar.gz "$STAGING"/.astral-final8-*.sha256 \
   "$STAGING"/.astral-final8-dirty.patch "$INPUT/"
mkdir -p "$SRC" "$BASE/logs"

test "$(sha256sum "$INPUT/.astral-final8-source.tar.gz" | cut -d' ' -f1)" = "$EXPECTED_SOURCE_TAR_SHA256"
test "$(sha256sum "$INPUT/.astral-final8-source-manifest.sha256" | cut -d' ' -f1)" = "$EXPECTED_SOURCE_MANIFEST_SHA256"
test "$(sha256sum "$INPUT/.astral-final8-dirty.patch" | cut -d' ' -f1)" = "$EXPECTED_DIRTY_PATCH_SHA256"
test "$(sha256sum "$INPUT/.astral-final8-harness.tar.gz" | cut -d' ' -f1)" = "$EXPECTED_HARNESS_TAR_SHA256"
test "$(sha256sum "$INPUT/.astral-final8-harness-manifest.sha256" | cut -d' ' -f1)" = "$EXPECTED_HARNESS_MANIFEST_SHA256"

tar -xzf "$INPUT/.astral-final8-source.tar.gz" -C "$SRC"
tar -xzf "$INPUT/.astral-final8-harness.tar.gz" -C "$SRC"
source_count=$(tar -tzf "$INPUT/.astral-final8-source.tar.gz" | wc -l)
harness_count=$(tar -tzf "$INPUT/.astral-final8-harness.tar.gz" | grep -cv '/$')
test "$source_count" -eq "$EXPECTED_SOURCE_COUNT"
test "$harness_count" -eq "$EXPECTED_HARNESS_COUNT"
sha256sum \
  "$INPUT/.astral-final8-source.tar.gz" \
  "$INPUT/.astral-final8-source-manifest.sha256" \
  "$INPUT/.astral-final8-dirty.patch" \
  "$INPUT/.astral-final8-harness.tar.gz" \
  "$INPUT/.astral-final8-harness-manifest.sha256" \
  > "$BASE/logs/input-checksums.txt"

cd "$SRC/AstralLight-Rust"
"$CARGO" build --release --bin astral-trustgraph --target-dir "$BASE/target"

cd "$SRC/AstralLight-Rust/bench/engine-comparison"
"$CARGO" build --release --bin engine-comparison --target-dir "$BASE/ec-target"

mkdir -p "$BASE/bootstrap/src"
cp "$SRC/Docs/实验/分布式测试/rust-s15/e2e-bootstrap-v2-main.rs" "$BASE/bootstrap/src/main.rs"
cat > "$BASE/bootstrap/Cargo.toml" <<'TOML'
[package]
name = "astral-e2e-bootstrap-final8"
version = "0.1.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
astral-db = { path = "../src/AstralLight-Rust/astral-db" }
astral-types = { path = "../src/AstralLight-Rust/astral-types" }
sqlx = { version = "0.8", features = ["runtime-tokio", "mysql", "time", "migrate"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
TOML
"$CARGO" build --release --manifest-path "$BASE/bootstrap/Cargo.toml" --target-dir "$BASE/bootstrap-target"

TRUST="$BASE/target/release/astral-trustgraph"
ENGINE="$BASE/ec-target/release/engine-comparison"
BOOT="$BASE/bootstrap-target/release/astral-e2e-bootstrap-final8"
test -x "$TRUST"
test -x "$ENGINE"
test -x "$BOOT"
file "$TRUST" "$ENGINE" "$BOOT" > "$BASE/logs/artifact-types.txt"
sha256sum "$TRUST" "$ENGINE" "$BOOT" > "$BASE/logs/artifact-sha256.txt"
printf 'BUILD_PASS\n' > "$BASE/logs/build.status"
cat "$BASE/logs/artifact-sha256.txt"
