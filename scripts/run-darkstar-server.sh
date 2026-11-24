#!/usr/bin/env bash
# Stage this checkout on an explicitly selected lab host. Never update an existing checkout.
set -euo pipefail
umask 077
export LC_ALL=C COPYFILE_DISABLE=1
usage() {
    printf '%s\n' 'Usage: bash scripts/run-darkstar-server.sh {pack|run|collect} SSH_ALIAS RUN_ID LOCAL_PARENT [--suite ID]...' \
        'pack builds and verifies a local source archive only (no SSH). Use a new ID for run.' \
        'run stages workspace inputs, runs the isolated MySQL campaign and retrieves its archive.' \
        'pack and run accept exact suite IDs; without them the full campaign runs as before.' \
        'collect retrieves an already finished run without launching it again.' >&2
    exit 64
}
[[ $# -ge 4 ]] || usage
mode=$1 host=$2 run=$3 parent=$4
shift 4
[[ $mode == pack || $mode == run || $mode == collect ]] || usage
[[ $host =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && $run =~ ^ds[a-z0-9_]{1,22}$ ]] || usage
suite_ids=()
campaign_selection=(--full)
while (($#)); do
    [[ $mode != collect && $# -ge 2 && $1 == --suite && $2 =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
    if ((${#suite_ids[@]} == 0)); then campaign_selection=(); fi
    suite_ids+=("$2")
    campaign_selection+=(--suite "$2")
    shift 2
done
ssh_args=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=4)
out="$(cd -- "$parent" && pwd -P)/$run"
remote="darkstar-test-runs/$run"
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
if [[ $mode != collect ]]; then
    mkdir -m 700 "$out"
    mkdir -m 700 "$out/stage"
    cd -- "$repo"
    paths=(Cargo.toml Cargo.lock rust-toolchain.toml .gitignore AGENTS.md README.md LICENSE docker-compose.test.yml
        'astral-*' policy-engine e2e-bootstrap integrations formal bench scripts tests-suite test-harness
        Docs/sql Docs/memory-v1 Docs/规范 Docs/authorization-validation
        # read_manifest verifies the provenance of non-selected suites as well.
        'Docs/实验/分布式测试/rust-s15/rq345_20260903.py' 'Docs/实验/分布式测试/rust-s15/s15_perf.py'
        'Docs/实验/分布式测试/rust-s15/test_s15_validation.py' 'Docs/实验/分布式测试/rust-s15/s15_validation.py')
    git ls-files -z --cached -- "${paths[@]}" > "$out/inputs.tracked"
    # Only Rust sources, the new clock crate's manifest and these entrypoints may be added outside the index.
    git ls-files -z --others --exclude-standard -- ':(glob)**/*.rs' astral-clock-source/Cargo.toml scripts/run-darkstar-server.sh scripts/run-darkstar-tests.sh scripts/provision-darkstar-mysql.sh > "$out/inputs.untracked"
    { sort -zu "$out/inputs.tracked" "$out/inputs.untracked"; } > "$out/inputs.list"
    while IFS= read -r -d '' p; do
        [[ -f $p && ! -L $p && $p != *$'\n'* && $p != *$'\r'* && $p != *\\* ]] || { printf 'Unsafe or missing input: %q\n' "$p" >&2; exit 65; }
    done < "$out/inputs.list"
    rsync -ar --from0 --files-from="$out/inputs.list" ./ "$out/stage/"
    git rev-parse HEAD > "$out/source-revision.txt"
    git status --short --branch > "$out/source-status.txt"
    (cd -- "$out/stage" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$out/source-files.sha256"
    # A portable archive without OSX xattrs, device records, Git objects or local credentials.
    (cd -- "$out/stage" && tar --format=ustar -czf "$out/source.tar.gz" --null -T "$out/inputs.list")
    (cd -- "$out" && sha256sum source.tar.gz source-files.sha256 source-revision.txt) > "$out/transport.sha256"
    (cd -- "$repo" && sha256sum -c "$out/source-files.sha256") > "$out/local-source-check.log"
    # List from the staged manifest, not the developer checkout. Keep build products
    # out of the source hash and refuse a partial bundle before reserving a host.
    (
        gate_target=$(mktemp -d "${TMPDIR:-/tmp}/darkstar-catalog-$run.XXXXXXXX")
        trap 'rm -rf -- "$gate_target"' EXIT
        cd -- "$out/stage"
        CARGO_TARGET_DIR="$gate_target" CARGO_INCREMENTAL=0 RUSTUP_AUTO_INSTALL=0 cargo run --locked --offline \
            -p test-harness --bin test-campaign -- --darkstar --mysql --run-id "$run" --list "${campaign_selection[@]}"
    ) > "$out/staged-catalog.json" 2> "$out/staged-catalog.stderr" || {
        printf 'Staged Rust catalog failed; see %s/staged-catalog.stderr\n' "$out" >&2; exit 65;
    }
    if [[ $mode == pack ]]; then printf 'Verified source: %s\n' "$out/source.tar.gz"; exit 0; fi
    # Atomic reservation: even a disconnected launch is never redispatched with this id.
    ssh "${ssh_args[@]}" "$host" "umask 077; mkdir -p darkstar-test-runs && mkdir '$remote'"
    scp "${ssh_args[@]}" "$out/"{source.tar.gz,source-files.sha256,source-revision.txt,transport.sha256} "$host:$remote/"
    # Optional offline Linux protoc, supplied by the operator; do not install anything on the host.
    if [[ -n ${DARKSTAR_LINUX_PROTOC_DIR:-} ]]; then
        tools=$(cd -- "$DARKSTAR_LINUX_PROTOC_DIR" && pwd -P)
        [[ -f $tools/bin/protoc && -d $tools/include && ! -L $tools/bin/protoc ]] || exit 66
        (cd -- "$tools" && tar --format=ustar -czf "$out/toolchain.tar.gz" bin/protoc include)
        (cd -- "$out" && sha256sum toolchain.tar.gz) > "$out/toolchain.sha256"
        scp "${ssh_args[@]}" "$out/"{toolchain.tar.gz,toolchain.sha256} "$host:$remote/"
    fi
    ssh "${ssh_args[@]}" "$host" bash -s -- "$run" "${suite_ids[@]+"${suite_ids[@]}"}" <<'REMOTE'
set -euo pipefail
umask 077
export LC_ALL=C
run=$1; base="$HOME/darkstar-test-runs/$run"
shift
selection=()
for id in "$@"; do selection+=(--suite "$id"); done
cd -- "$base"
sha256sum -c transport.sha256
if [[ -f toolchain.sha256 ]]; then
    sha256sum -c toolchain.sha256
    mkdir -m 700 tools
    tar -xzf toolchain.tar.gz -C tools
    tools/bin/protoc --version
fi
mkdir -m 700 source
(cd source && tar -xzf ../source.tar.gz && sha256sum -c ../source-files.sha256) > source-check.log
image=$(docker image inspect mysql:8.0 --format '{{.Id}}')
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]]
# A single detached owner survives SSH disconnects. Inspect before any subsequent action.
mkdir launch-claim
nohup setsid bash -c '
    umask 077; set -u
    base=$1 run=$2 image=$3
    shift 3
    export PATH="$base/tools/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" LC_ALL=C
    if [[ -x $base/tools/bin/protoc ]]; then export PROTOC="$base/tools/bin/protoc"; fi
    cd -- "$base" || exit 71
    { date -u +%FT%TZ; rustc -Vv; cargo -V; lscpu; uname -srmo; df -h . /tmp; free -h; taskset -pc $$; } > environment.log
    timeout --kill-after=90s 6h bash source/scripts/run-darkstar-tests.sh --provision-mysql --run-id "$run" --run-dir "$base" --mysql-image "$image" "$@"
    rc=$?
    printf "%s\n" "$rc" > campaign.exit
    bundle_inputs=(campaign.exit source-check.log source-files.sha256 source-revision.txt transport.sha256 environment.log launch.log)
    if [[ -d evidence ]]; then
        # Only the Rust-owned bundle has verified/sanitized suite streams. Do not
        # recursively export partial, possibly credential-bearing output.
        for f in evidence/*.tar.gz evidence/*.txt evidence/*.tsv evidence/*.sha256 evidence/*.check evidence/*.zlist evidence/*.cid evidence/catalog.json evidence/cargo-size-profile.toml evidence/server.log evidence/accounts.log evidence/*schema*.log evidence/container-remove.log evidence/workspace; do
            if [[ -e $f && ! -L $f ]]; then bundle_inputs+=("$f"); fi
        done
    fi
    if [[ -f toolchain.sha256 ]]; then bundle_inputs+=(toolchain.sha256); fi
    # Retain the exact timed RQ3 executable (not only a historical digest).
    if [[ -d measured-binaries && ! -L measured-binaries ]]; then
        (cd measured-binaries && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) > measured-binaries.sha256
        bundle_inputs+=(measured-binaries measured-binaries.sha256)
    fi
    if tar -czf "$run-evidence.tar.gz.part" "${bundle_inputs[@]}" && mv -- "$run-evidence.tar.gz.part" "$run-evidence.tar.gz" && sha256sum "$run-evidence.tar.gz" > evidence.sha256; then :; else rc=74; fi
    printf "%s\n" "$rc" > terminal.part && mv -- terminal.part terminal.exit
' runner "$base" "$run" "$image" "${selection[@]}" </dev/null >launch.log 2>&1 &
REMOTE
    # This waits, but never starts or retries a remote process. After a transport failure use collect.
    ssh "${ssh_args[@]}" "$host" "cd '$remote' && timeout 21900 bash -c 'until test -f terminal.exit; do sleep 10; done'"
fi
[[ -d $out && ! -L $out ]] || { printf 'Missing local run directory: %s\n' "$out" >&2; exit 66; }
receipt=$(mktemp -d "$out/receipt.XXXXXXXX")
scp "${ssh_args[@]}" "$host:$remote/terminal.exit" "$host:$remote/launch.log" "$receipt/"
scp "${ssh_args[@]}" "$host:$remote/$run-evidence.tar.gz" "$host:$remote/evidence.sha256" "$receipt/"
(cd -- "$receipt" && sha256sum -c evidence.sha256)
printf 'Verified receipt: %s\n' "$receipt"
read -r rc < "$receipt/terminal.exit"
[[ $rc =~ ^[0-9]{1,3}$ ]] && exit "$rc"
exit 74
