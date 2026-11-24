#!/usr/bin/env bash
# Launch the Rust campaign, or provision one isolated experimental MySQL fixture.
set -euo pipefail
umask 077
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$source_dir"
export RUSTUP_AUTO_INSTALL=0

if [[ ${1:-} != --provision-mysql ]]; then
    exec cargo run --locked --offline -p test-harness --bin test-campaign -- --darkstar "$@"
fi
shift

# Source and its externally generated manifest must already be in the private
# server run directory. Without selectors keep the original full campaign.
run='' base='' image='' selected=0
selection=(--full)
while (($#)); do
    case $1 in
        --run-id) (($# >= 2)) || exit 64; run=$2; shift 2 ;;
        --run-dir) (($# >= 2)) || exit 64; base=$2; shift 2 ;;
        --mysql-image) (($# >= 2)) || exit 64; image=$2; shift 2 ;;
        --suite)
            [[ $# -ge 2 && $2 =~ ^[a-z0-9][a-z0-9_-]*$ ]] || exit 64
            if (( !selected )); then selection=(); fi
            selected=1
            selection+=(--suite "$2")
            shift 2
            ;;
        *) printf 'unknown provisioning argument: %s\n' "$1" >&2; exit 64 ;;
    esac
done
[[ $run =~ ^ds[0-9a-z_]{1,24}$ ]] || { printf 'invalid run id\n' >&2; exit 64; }
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'provide a local immutable MySQL image ID\n' >&2; exit 64; }
[[ -n $base && -d $base && ! -L $base ]] || { printf 'existing private run directory required\n' >&2; exit 64; }
base=$(cd -- "$base" && pwd -P)
[[ $(stat -c %u "$base") == "$(id -u)" && $(stat -c %a "$base") == 700 ]] || {
    printf 'run directory must be owned by this user and mode 700\n' >&2; exit 64;
}
[[ $source_dir == "$base/source" && -f $base/source-files.sha256 && ! -L $base/source-files.sha256 ]] || {
    printf 'expected run-dir/source and run-dir/source-files.sha256\n' >&2; exit 64;
}
[[ $(id -u) != 0 ]] || { printf 'run as the unprivileged source owner\n' >&2; exit 64; }
# A fresh evidence directory is the one-shot claim; never overwrite an old run.
mkdir -m 700 -- "$base/evidence" || { printf 'run already claimed or evidence unavailable\n' >&2; exit 73; }
evidence="$base/evidence"
exec > >(tee -a "$evidence/server.log") 2>&1
printf 'run=%s started=%s source=%s\n' "$run" "$(date -u +%FT%TZ)" "$source_dir"
cid='' token='' build_tmp='' private_created=0 source_verified=0 secret="$base/private/mysql.env" clean=1
cleanup() {
    local rc=$? label container_token
    trap - EXIT INT TERM
    set +e
    if [[ -z $cid && -s $evidence/container.cid ]]; then
        read -r cid < "$evidence/container.cid"
    fi
    if [[ -n $cid ]]; then
        label=$(docker inspect -f '{{index .Config.Labels "dev.astrallight.darkstar.test-run"}}' "$cid" 2>/dev/null)
        container_token=$(docker inspect -f '{{index .Config.Labels "dev.astrallight.darkstar.token"}}' "$cid" 2>/dev/null)
        if [[ $label == "$run" && -n $token && $container_token == "$token" ]]; then
            docker logs "$cid" > "$evidence/mysql-container.log" 2>&1 || clean=0
            docker rm -f "$cid" > "$evidence/container-remove.log" 2>&1 || clean=0
            if docker inspect "$cid" >/dev/null 2>&1; then clean=0; fi
        else
            printf 'container ownership unknown; manual reconciliation required: %s\n' "$cid"
            clean=0
        fi
    fi
    if (( source_verified )); then
        find . -path ./.git -prune -o -type l -print > "$evidence/source-symlinks-after.txt" || clean=0
        [[ ! -s $evidence/source-symlinks-after.txt ]] || clean=0
        source_check after || { printf 'source changed during run\n'; clean=0; }
    fi
    if (( private_created )); then
        rm -f -- "$secret" || clean=0
        rmdir -- "$base/private" || clean=0
    fi
    if [[ -n $build_tmp ]]; then
        if [[ $build_tmp == /tmp/darkstar-target-"$run".* && -d $build_tmp && ! -L $build_tmp && -O $build_tmp ]]; then
            du -sh -- "$build_tmp" > "$evidence/build-size.txt" || clean=0
            if (( !selected )) && [[ -d $build_tmp/release/deps ]]; then
                mkdir -m 700 -- "$base/measured-binaries" || clean=0
                find "$build_tmp/release/deps" -maxdepth 1 -type f -name 'policy_engine-*' -perm -100 -exec cp -p -- {} "$base/measured-binaries/" \; || clean=0
            fi
            rm -rf -- "$build_tmp" || clean=0
        fi
        [[ ! -e $build_tmp && ! -L $build_tmp ]] || clean=0
    fi
    printf '%s\n' "$rc" > "$evidence/entry-exit.txt"
    printf '%s\n' "$clean" > "$evidence/cleanup-ok.txt"
    printf 'finished=%s entry_exit=%s cleanup_ok=%s\n' "$(date -u +%FT%TZ)" "$rc" "$clean"
    (( clean == 1 )) || exit 70
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ $(uname -s) == Linux ]] || { printf 'BLOCKED: Linux required\n'; exit 69; }
for cmd in docker sudo nsenter setpriv openssl perl sha256sum find sort xargs cmp cargo rustc tee tar git timeout; do
    command -v "$cmd" >/dev/null || { printf 'BLOCKED: missing %s\n' "$cmd"; exit 69; }
done
[[ -x /usr/bin/nsenter && -x /usr/bin/setpriv && -x /usr/bin/env && -x /bin/bash ]] || {
    printf 'BLOCKED: required namespace tools unavailable at standard paths\n'; exit 69;
}
sudo -n true || { printf 'BLOCKED: passwordless sudo required for nsenter\n'; exit 69; }
docker image inspect "$image" --format '{{.Id}} {{.Os}}/{{.Architecture}}' > "$evidence/image.txt" || {
    printf 'BLOCKED: approved MySQL image not present locally\n'; exit 69;
}
# Reject an existing repository and symlinks: neither is covered by the file manifest.
[[ ! -e .git && ! -L .git ]] || { printf 'BLOCKED: source already has .git\n'; exit 65; }
find . -type l -print > "$evidence/source-symlinks.txt"
[[ ! -s $evidence/source-symlinks.txt ]] || { printf 'BLOCKED: source contains symlinks\n'; exit 65; }
cp -- "$base/source-files.sha256" "$evidence/source-files.sha256"
source_check() {
    local phase=$1
    LC_ALL=C find . -path ./.git -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum > "$evidence/source-$phase.sha256" || return 1
    cmp -- "$evidence/source-files.sha256" "$evidence/source-$phase.sha256" > "$evidence/source-$phase.check" 2>&1
}
source_check before || { printf 'BLOCKED: source manifest mismatch\n'; exit 65; }
source_verified=1
# The Rust harness enumerates source through git. This new local index contains
# precisely the transferred files; it has no remote, commit, or shared hooks.
git init -q --template='' .
git -c core.hooksPath=/dev/null add -f -- .
git ls-files -z > "$evidence/git-files.zlist"
rustc --version --verbose
cargo --version
mkdir -m 700 -- "$base/scratch"
available=$(df -k --output=avail /tmp | tr -cd '0-9')
[[ $(findmnt -n -T /tmp -o FSTYPE) == tmpfs && $available =~ ^[0-9]+$ ]] && (( available >= 12 * 1024 * 1024 )) || {
    printf 'BLOCKED: campaign requires 12 GiB free on /tmp tmpfs\n'
    exit 69
}
build_tmp=$(mktemp -d "/tmp/darkstar-target-$run.XXXXXXXX")
CARGO_TARGET_DIR="$build_tmp"
if (( !selected )); then
    # This parent config applies to every invocation, including nested test
    # targets. Keep optimization, assertions and overflow checks unchanged.
    mkdir -m 700 -- "$base/.cargo"
    printf '%s\n' '[profile.dev]' 'debug = "none"' 'strip = "symbols"' '[profile.test]' 'debug = "none"' 'strip = "symbols"' > "$base/.cargo/config.toml"
    cp -- "$base/.cargo/config.toml" "$evidence/cargo-size-profile.toml"
fi
printf '%s\n' "$CARGO_TARGET_DIR" > "$evidence/build-target.txt"
export CARGO_TARGET_DIR CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-6}
export TMPDIR="$base/scratch"
cargo build --offline --locked -j "$CARGO_BUILD_JOBS" -p test-harness --bin test-campaign
"$CARGO_TARGET_DIR/debug/test-campaign" --darkstar --mysql --run-id "$run" --list "${selection[@]}" > "$evidence/catalog.json"

mkdir -m 700 -- "$base/private"
private_created=1
export MYSQL_ROOT_PASSWORD="$(openssl rand -hex 24)"
paper_password=$(openssl rand -hex 24)
apply_password=$(openssl rand -hex 24)
cold_password=$(openssl rand -hex 24)
e2e_password=$(openssl rand -hex 24)
token=$(openssl rand -hex 12)
# The image is already local, has no host network/port bindings, and stores
# data in tmpfs. Never attach a host volume or a shared database.
cid=$(docker create --cidfile "$evidence/container.cid" --name "darkstar-$run-$token" --label "dev.astrallight.darkstar.test-run=$run" \
    --label "dev.astrallight.darkstar.token=$token" --pull=never --network none \
    --memory 1536m --cpus 4 --pids-limit 512 --tmpfs /var/lib/mysql:rw,nosuid,nodev,size=1536m \
    --env MYSQL_ROOT_PASSWORD "$image" --bind-address=127.0.0.1 --port=3308 \
    --partial-revokes=ON --innodb-buffer-pool-size=192M)
unset MYSQL_ROOT_PASSWORD
printf '%s\n' "$cid" > "$evidence/container-id.txt"
docker start "$cid" >/dev/null
ready=0
for ((probe=1; probe<=45; probe++)); do
    if docker exec "$cid" sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --protocol=tcp -h127.0.0.1 -P3308 -uroot -Nse "SELECT VERSION(), @@port, @@skip_networking"' > "$evidence/mysql-readiness.txt" 2> "$evidence/mysql-readiness.stderr"; then
        ready=1; break
    fi
    sleep 2
done
[[ $ready == 1 ]] || { printf 'BLOCKED: isolated MySQL did not become ready\n'; exit 69; }
[[ $(docker inspect -f '{{index .Config.Labels "dev.astrallight.darkstar.test-run"}}' "$cid") == "$run" ]]
[[ $(docker inspect -f '{{index .Config.Labels "dev.astrallight.darkstar.token"}}' "$cid") == "$token" ]]
[[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$cid") == none ]]
docker inspect -f '{{.Id}} {{.Image}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}} {{.State.Pid}}' "$cid" > "$evidence/mysql-isolation.txt"
pid=$(docker inspect -f '{{.State.Pid}}' "$cid")
mysql() { docker exec -i "$cid" sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --protocol=socket -uroot "$@"' mysql "$@"; }
candidate_ddl() { perl -ne 'if (/^\/\* OFFLINE CANDIDATE:/) {$inside=1;next} if (/^\*\//) {$inside=0} print if $inside' "$@"; }
paper="astral_rehearsal_paper_$run" apply="astral_rehearsal_apply_$run" cold="astral_rehearsal_cold_$run"
printf 'CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\n' "$paper" "$apply" "$cold" | mysql > "$evidence/schema-create.log" 2>&1
# All three isolated schemas have nine fact tables and the four recovery tables.
# Preparation signs only a fresh paper fixture; the measured reader does not create history.
for schema in "$paper" "$apply" "$cold"; do
    candidate_ddl 'Docs/memory-v1/数据库结构候选.sql' 'Docs/sql/memory-v1-apply-candidate.sql' | mysql --database="$schema" > "$evidence/$schema-schema.log" 2>&1
done
set +e
{
    printf "CREATE USER 'darkstar_paper'@'%%' IDENTIFIED BY '%s';\n" "$paper_password"
    printf "CREATE USER 'darkstar_apply'@'%%' IDENTIFIED BY '%s';\n" "$apply_password"
    printf "CREATE USER 'darkstar_cold'@'%%' IDENTIFIED BY '%s';\n" "$cold_password"
    printf "CREATE USER 'darkstar_e2e'@'%%' IDENTIFIED BY '%s';\n" "$e2e_password"
    printf "GRANT SELECT, INSERT ON \x60%s\x60.* TO 'darkstar_paper'@'%%';\n" "$paper"
    printf "GRANT SELECT, INSERT, UPDATE, DELETE ON \x60%s\x60.* TO 'darkstar_apply'@'%%';\n" "$apply"
    printf "GRANT SELECT, INSERT, UPDATE, DELETE ON \x60%s\x60.* TO 'darkstar_cold'@'%%';\n" "$cold"
    # With partial_revokes=ON underscores are literal. The fixture CREATE has
    # no IF NOT EXISTS; a collision is a failure, never permission to clean up.
    for lane in binary transport negative positive; do
        schema_hash=$(printf '%s:%s' "$run" "$lane" | sha256sum) || exit 65
        [[ ${schema_hash:0:16} =~ ^[0-9a-f]{16}$ ]] || exit 65
        printf "GRANT SELECT, INSERT, UPDATE, CREATE, DROP, ALTER, INDEX, REFERENCES ON \x60astral_rehearsal_mv1_%s\x60.* TO 'darkstar_e2e'@'%%';\n" "${schema_hash:0:16}"
    done
} | mysql > /dev/null 2>&1
accounts_rc=$?
set -e
printf '%s\n' "$accounts_rc" > "$evidence/accounts-exit.txt"
if (( accounts_rc != 0 )); then
    printf 'account provisioning failed; credential-bearing SQL diagnostics suppressed\n' > "$evidence/accounts.log"
    exit "$accounts_rc"
fi
printf 'account provisioning completed\n' > "$evidence/accounts.log"
# Retain this synthetic bundle on the private run host, outside the exported evidence.
mkdir -m 700 -- "$base/paper-startup-$run"
{
    printf 'export ASTRAL_PAPER_STARTUP_BUNDLE_DIR=%q\n' "$base/paper-startup-$run"
    printf 'export ASTRAL_PAPER_PREPARE_APPROVED_RUN=%s\n' "$run"
    printf 'export ASTRAL_DARKSTAR_MYSQL_APPROVED_RUN=%s\n' "$run"
    printf 'export ASTRAL_PAPER_MYSQL_APPROVED_RUN=%s\n' "$run"
    printf 'export ASTRAL_PAPER_MYSQL_URL=mysql://darkstar_paper:%s@127.0.0.1:3308/%s\n' "$paper_password" "$paper"
    printf 'export ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL=mysql://darkstar_apply:%s@127.0.0.1:3308/%s\n' "$apply_password" "$apply"
    printf 'export ASTRAL_DARKSTAR_COLD_MYSQL_URL=mysql://darkstar_cold:%s@127.0.0.1:3308/%s\n' "$cold_password" "$cold"
    printf 'export ASTRAL_MEMORY_V1_E2E_ADMIN_URL=mysql://darkstar_e2e:%s@127.0.0.1:3308/\n' "$e2e_password"
} > "$secret"
unset paper_password apply_password cold_password e2e_password
mysql -N -e "SELECT TABLE_SCHEMA,COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('$paper','$apply','$cold') GROUP BY TABLE_SCHEMA" > "$evidence/mysql-tables-before.tsv"
printf 'campaign start=%s\n' "$(date -u +%FT%TZ)"
set +e
sudo -n /usr/bin/nsenter --target "$pid" --net -- /usr/bin/setpriv --reuid "$(id -u)" --regid "$(id -g)" --clear-groups -- \
    /usr/bin/env -i HOME="$HOME" PATH="$PATH" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS" CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 TMPDIR="$TMPDIR" PROTOC="${PROTOC:-protoc}" \
    /bin/bash -c 'set -e; source "$1"; shift; exec bash scripts/run-darkstar-tests.sh "$@"' bash "$secret" \
    --mysql --run-id "$run" --artifact-root "$evidence" "${selection[@]}"
campaign_rc=$?
set -e
printf '%s\n' "$campaign_rc" > "$evidence/campaign-exit.txt"
printf 'campaign finished=%s exit=%s\n' "$(date -u +%FT%TZ)" "$campaign_rc"
mysql -N -e "SELECT TABLE_SCHEMA,COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('$paper','$apply','$cold') GROUP BY TABLE_SCHEMA; SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME REGEXP '^astral_rehearsal_mv1_[0-9a-f]{16}$'" > "$evidence/mysql-tables-after.tsv" 2> "$evidence/mysql-tables-after.stderr" || clean=0
for schema in "$apply" "$cold"; do
    mysql --database="$schema" -N -e 'SELECT COUNT(*), COALESCE(SUM(last_journal_sequence),0) FROM mv1_apply_progress; SELECT COUNT(*) FROM mv1_apply_receipt; SELECT COUNT(*) FROM mv1_apply_audit_event; SELECT COUNT(*) FROM mv1_apply_fence WHERE lease_expires_at > CURRENT_TIMESTAMP(6);' > "$evidence/$schema-after.tsv" 2> "$evidence/$schema-after.stderr" || clean=0
done

# These standard Cargo gates are separate from the measured campaign. Revoke
# the test accounts and remove fixture credentials before entering the same
# isolated network namespace with a fresh environment. Keep the server alive to
# retain its namespace; the container and its data are removed during cleanup.
mysql -e "DROP USER 'darkstar_paper'@'%', 'darkstar_apply'@'%', 'darkstar_cold'@'%', 'darkstar_e2e'@'%'" > /dev/null 2>&1 || {
    printf 'BLOCKED: could not revoke fixture accounts before workspace gates\n'
    exit 70
}
rm -f -- "$secret"
rmdir -- "$base/private"
private_created=0
# Compile test targets only: workspace and nested consumer catalogs contain
# negative or fault-injection cases outside the approved campaign selection.
mkdir -m 700 -- "$evidence/workspace"
workspace_failed=0
workspace_gate() {
    local name=$1 limit=$2 rc
    shift 2
    local -a command=(timeout --signal=TERM --kill-after=30s "$limit" sudo -n /usr/bin/nsenter --target "$pid" --net --
        /usr/bin/setpriv --reuid "$(id -u)" --regid "$(id -g)" --clear-groups --
        /usr/bin/env -i HOME="$HOME" PATH="$PATH" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS" CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
        RUSTUP_AUTO_INSTALL=0 TMPDIR="$TMPDIR" PROTOC="${PROTOC:-protoc}" "$@")
    printf '%q ' "${command[@]}" > "$evidence/workspace/$name.argv"
    printf '\n' >> "$evidence/workspace/$name.argv"
    printf '%s\n' "$(date -u +%FT%TZ)" > "$evidence/workspace/$name.start"
    set +e
    "${command[@]}" > "$evidence/workspace/$name.stdout.log" 2> "$evidence/workspace/$name.stderr.log"
    rc=$?
    set -e
    printf '%s\n' "$(date -u +%FT%TZ)" > "$evidence/workspace/$name.end"
    printf '%s\n' "$rc" > "$evidence/workspace/$name.exit"
    printf 'workspace gate=%s exit=%s\n' "$name" "$rc"
    (( rc == 0 )) || workspace_failed=1
}
workspace_gate fmt 600s cargo --offline --locked fmt --all -- --check
if (( selected )); then
    printf 'not run for explicit suite selection: workspace check, clippy, test compile, integrations test compile\n' > "$evidence/workspace/selection-scope.txt"
else
    workspace_gate check 3600s cargo --offline --locked check --workspace
    workspace_gate clippy 3600s cargo --offline --locked clippy --workspace -- -D warnings
    workspace_gate test-compile 10800s cargo --offline --locked test --workspace --no-run
    workspace_gate integrations-test-compile 3600s cargo --offline --locked test --manifest-path integrations/Cargo.toml --workspace --no-run
fi
printf '%s\n' "$workspace_failed" > "$evidence/workspace/failed.txt"
if (( campaign_rc != 0 )); then exit "$campaign_rc"; fi
if (( workspace_failed != 0 )); then exit 1; fi
exit 0
