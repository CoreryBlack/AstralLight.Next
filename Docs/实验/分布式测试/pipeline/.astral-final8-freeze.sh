#!/usr/bin/env bash
# final8 source+harness freeze. Runs LOCALLY from its pipeline directory
# (Windows git-bash); writes outputs next to itself and operates on the repo
# root four levels up.
# Recipe (matches final4-final7 semantics):
#   source tar   = git ls-files (tracked index paths, working-tree content)
#   manifest     = "sha256  path\n" (two spaces, LF, UTF-8) over the same list
#   dirty patch  = git diff HEAD --binary (tracked divergence vs HEAD)
#   harness tar  = the 10-file rust-s15 allowlist, repo-root relative paths
#   harness man. = "sha256  name\n" relative to the harness dir (sha256sum -c)
# Outputs identity lines consumed by the build/deploy/setup/campaign wrappers.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "$ROOT"

RUN=final8
SRC_TAR="$SCRIPT_DIR/.astral-${RUN}-source.tar.gz"
SRC_MANIFEST="$SCRIPT_DIR/.astral-${RUN}-source-manifest.sha256"
DIRTY_PATCH="$SCRIPT_DIR/.astral-${RUN}-dirty.patch"
HARNESS_TAR="$SCRIPT_DIR/.astral-${RUN}-harness.tar.gz"
HARNESS_MANIFEST="$SCRIPT_DIR/.astral-${RUN}-harness-manifest.sha256"
FILELIST="$SCRIPT_DIR/.astral-${RUN}-filelist.txt"
IDENTITIES="$SCRIPT_DIR/.astral-${RUN}-identities.txt"

rm -f "$SRC_TAR" "$SRC_MANIFEST" "$DIRTY_PATCH" "$HARNESS_TAR" \
      "$HARNESS_MANIFEST" "$FILELIST" "$IDENTITIES"

# 1) tracked index paths (staged deletions are already absent from ls-files)
git -c core.quotepath=off ls-files > "$FILELIST"
COUNT=$(wc -l < "$FILELIST")
echo "filelist entries: $COUNT"

# 2) source tar from working tree content
tar -czf "$SRC_TAR" -T "$FILELIST"
TAR_COUNT=$(tar -tzf "$SRC_TAR" | wc -l)
test "$TAR_COUNT" -eq "$COUNT"

# 3) deterministic per-file manifest (digest + two spaces + path, LF)
python - "$FILELIST" "$SRC_MANIFEST" <<'PY'
import hashlib, sys

list_path, out_path = sys.argv[1], sys.argv[2]
with open(list_path, encoding="utf-8") as handle:
    paths = [line.rstrip("\n") for line in handle if line.strip()]
with open(out_path, "w", encoding="utf-8", newline="\n") as out:
    for rel in paths:
        with open(rel, "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
        out.write("%s  %s\n" % (digest, rel))
print("manifest entries:", len(paths))
PY

# 4) dirty patch (tracked divergence vs HEAD, incl. staged deletions)
git -c core.quotepath=off diff HEAD --binary > "$DIRTY_PATCH"

# 5) harness tar (10 allowlist files, repo-root relative) + manifest
HDIR="Docs/实验/分布式测试/rust-s15"
HFILES="deploy_dist.sh e2e-bootstrap-v2-main.rs f7_recheck.py rq345_20260903.py \
rq_fill_20260901.py run_cs_evidence.py s15_coordinator.py s15_perf.py \
seed_f4rust.sql README.md"
tar -czf "$HARNESS_TAR" $(for f in $HFILES; do printf '%s/%s ' "$HDIR" "$f"; done)
HCOUNT=$(tar -tzf "$HARNESS_TAR" | grep -cv '/$')
test "$HCOUNT" -eq 10
python - "$HDIR" "$HARNESS_MANIFEST" $HFILES <<'PY'
import hashlib, os, sys

hdir, out_path, names = sys.argv[1], sys.argv[2], sys.argv[3:]
with open(out_path, "w", encoding="utf-8", newline="\n") as out:
    for name in names:
        with open(os.path.join(hdir, name), "rb") as stream:
            digest = hashlib.sha256(stream.read()).hexdigest()
        out.write("%s  %s\n" % (digest, name))
print("harness manifest entries:", len(names))
PY
( cd "$HDIR" && sha256sum -c "../pipeline/.astral-${RUN}-harness-manifest.sha256" > /dev/null )

# 6) combined harness identity (must equal run_cs_evidence.harness_sha256)
COMBINED=$(python - "$HDIR" $HFILES <<'PY'
import hashlib, os, sys

root, names = sys.argv[1], sys.argv[2:]
h = hashlib.sha256()
for name in names:
    d = hashlib.sha256(open(os.path.join(root, name), "rb").read()).hexdigest()
    h.update(name.encode()); h.update(b"\0"); h.update(d.encode()); h.update(b"\n")
print(h.hexdigest())
PY
)

# 7) identity summary
TOCTOU_SHA=$(python - <<'PY'
import hashlib
print(hashlib.sha256(open(r"AstralLight-Rust/bench/loadgen/scripts/toctou_race.py",
                         "rb").read()).hexdigest())
PY
)
{
  echo "SOURCE_COUNT=$COUNT"
  echo "SOURCE_TAR_SHA256=$(sha256sum "$SRC_TAR" | cut -d' ' -f1)"
  echo "SOURCE_MANIFEST_SHA256=$(sha256sum "$SRC_MANIFEST" | cut -d' ' -f1)"
  echo "DIRTY_PATCH_SHA256=$(sha256sum "$DIRTY_PATCH" | cut -d' ' -f1)"
  echo "HARNESS_TAR_SHA256=$(sha256sum "$HARNESS_TAR" | cut -d' ' -f1)"
  echo "HARNESS_MANIFEST_SHA256=$(sha256sum "$HARNESS_MANIFEST" | cut -d' ' -f1)"
  echo "HARNESS_COMBINED_SHA256=$COMBINED"
  echo "TOCTOU_SHA256=$TOCTOU_SHA"
  echo "GIT_REV=$(git rev-parse HEAD)"
} | tee "$IDENTITIES"
echo "FREEZE_PASS $RUN"
